from __future__ import annotations

import json
import tempfile
from pathlib import Path

from fastapi import FastAPI, File, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware

from .config import settings
from .models import AnalyzeResponse, CallAnalysis, Diagnosis, HealthResponse, Summary
from .report import build_markdown_report
from .rtp_parser import analyze_rtp, build_rtp_legs, compare_sdp_to_rtp, extract_audio_streams
from .sip_parser import analyze_sip
from .tshark import tshark_available, tshark_version


app = FastAPI(title=settings.app_name)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/api/health", response_model=HealthResponse)
def health() -> HealthResponse:
    available = tshark_available()
    return HealthResponse(
        status="ok" if available else "degraded",
        tshark_available=available,
        tshark_version=tshark_version(),
        max_upload_mb=settings.max_upload_mb,
    )


def _validate_upload(file: UploadFile) -> None:
    filename = file.filename or ""
    suffix = Path(filename).suffix.lower()
    if suffix not in {".pcap", ".pcapng"}:
        raise HTTPException(status_code=400, detail="Arquivo deve ter extensao .pcap ou .pcapng")
    if not tshark_available():
        raise HTTPException(status_code=503, detail="tshark nao encontrado no PATH")


async def _save_upload(file: UploadFile) -> Path:
    settings.upload_dir.mkdir(parents=True, exist_ok=True)
    suffix = Path(file.filename or "").suffix.lower()
    handle = tempfile.NamedTemporaryFile(delete=False, suffix=suffix, dir=settings.upload_dir)
    path = Path(handle.name)
    size = 0

    try:
        with handle:
            while chunk := await file.read(1024 * 1024):
                size += len(chunk)
                if size > settings.max_upload_bytes:
                    raise HTTPException(
                        status_code=413,
                        detail=f"Arquivo excede o limite de {settings.max_upload_mb} MB",
                    )
                handle.write(chunk)
    except Exception:
        path.unlink(missing_ok=True)
        raise

    return path


def _empty_analysis(filename: str, warnings: list[str]) -> AnalyzeResponse:
    diagnosis = Diagnosis(
        probable_cause="PCAP sem sinalizacao SIP detectavel",
        resolution="Confirmar filtro/captura, porta SIP, descriptografia se houver TLS e se o arquivo contem pacotes SIP.",
        severity="warning",
        category="no_sip",
        evidence=["Nenhum pacote SIP foi identificado"],
        suggested_checks=["Confirmar filtro/captura", "Verificar SIP TLS ou portas nao padrao"],
        confidence="medium",
    )
    call = CallAnalysis(
        call_id="sem-sip",
        status="warning",
        final_sip_code=None,
        final_reason=None,
        duration_seconds=None,
        codec=[],
        diagnosis=diagnosis,
        technical={},
    )
    return AnalyzeResponse(
        filename=filename,
        summary=Summary(total_calls=0, failed_calls=0, successful_calls=0),
        calls=[call],
        warnings=warnings,
    )


def _severity_rank(severity: str) -> int:
    return {"info": 0, "warning": 1, "critical": 2}.get(severity, 1)


def _apply_diagnosis(call: CallAnalysis, diagnosis: Diagnosis) -> None:
    if _severity_rank(diagnosis.severity) >= _severity_rank(call.diagnosis.severity):
        call.diagnosis = diagnosis
    if diagnosis.severity == "critical":
        call.status = "failed"
    elif diagnosis.severity == "warning" and call.status == "success":
        call.status = "warning"


def _rtp_sequence_summary(audio_streams: list) -> list[dict[str, object]]:
    summary: list[dict[str, object]] = []
    for stream in audio_streams:
        if (
            stream.sequence_gap_count
            or stream.lost_packet_count
            or stream.duplicate_packet_count
            or stream.out_of_order_packet_count
        ):
            summary.append(
                {
                    "stream_id": stream.stream_id,
                    "source": stream.source,
                    "source_port": stream.source_port,
                    "destination": stream.destination,
                    "destination_port": stream.destination_port,
                    "ssrc": stream.ssrc,
                    "packet_count": stream.packet_count,
                    "expected_packet_count": stream.expected_packet_count,
                    "sequence_gap_count": stream.sequence_gap_count,
                    "lost_packet_count": stream.lost_packet_count,
                    "duplicate_packet_count": stream.duplicate_packet_count,
                    "out_of_order_packet_count": stream.out_of_order_packet_count,
                    "max_sequence_gap": stream.max_sequence_gap,
                    "gaps": stream.rtp_sequence_gaps,
                }
            )
    return summary


def _enrich_technical_diagnosis(call: CallAnalysis, sdp_rtp_comparison: list[dict[str, object]]) -> None:
    if not call.final_sip_code or not 200 <= call.final_sip_code < 300:
        return

    retransmissions = call.technical.get("sip_retransmissions")
    retransmission_count = 0
    if isinstance(retransmissions, list):
        retransmission_count = sum(int(item.get("retransmission_count", 0)) for item in retransmissions if isinstance(item, dict))

    expected_problem_legs = [
        leg for leg in call.rtp_legs if leg.leg_id.startswith("expected-") and leg.status in {"missing", "no_audio"}
    ]
    missing_legs = [leg for leg in expected_problem_legs if leg.status == "missing"]
    no_audio_legs = [leg for leg in expected_problem_legs if leg.status == "no_audio"]
    missing_sdp = [item for item in sdp_rtp_comparison if item.get("type") == "missing_rtp"]
    unexpected_rtp = [item for item in sdp_rtp_comparison if item.get("type") == "unexpected_rtp"]
    payload_mismatch = [item for item in sdp_rtp_comparison if item.get("type") == "payload_mismatch"]
    sequence_summary = _rtp_sequence_summary(call.audio_streams)
    sequence_lost = sum(int(item["lost_packet_count"]) for item in sequence_summary)

    call.media.sequence_gap_count = sum(stream.sequence_gap_count for stream in call.audio_streams)
    call.media.duplicate_packet_count = sum(stream.duplicate_packet_count for stream in call.audio_streams)
    call.media.out_of_order_packet_count = sum(stream.out_of_order_packet_count for stream in call.audio_streams)

    if missing_legs and len(missing_legs) >= 2:
        _apply_diagnosis(
            call,
            Diagnosis(
                probable_cause="Chamada estabelecida, mas sem RTP nas pernas esperadas pelo SDP",
                resolution="Validar NAT/firewall, SBC, ACLs UDP e se os IPs/portas anunciados no SDP sao alcancaveis.",
                severity="critical",
                category="no_way_audio",
                evidence=[
                    "SIP final 2xx indica chamada estabelecida",
                    f"{len(missing_legs)} pernas RTP esperadas pelo SDP nao chegaram ao PCAP",
                ],
                suggested_checks=["Conferir c= e m= no SDP", "Validar liberacao UDP das portas RTP", "Checar roteamento/NAT entre as pontas"],
                confidence="high",
            ),
        )
    elif expected_problem_legs or (call.media.rtp_detected and call.media.directions == 1):
        evidence = ["SIP final 2xx indica chamada estabelecida"]
        if missing_legs:
            evidence.append(f"{len(missing_legs)} perna(s) RTP esperada(s) pelo SDP sem pacotes")
        if no_audio_legs:
            evidence.append(f"{len(no_audio_legs)} perna(s) RTP com pacotes, mas sem voz util")
        if call.media.directions == 1:
            evidence.append("Apenas uma direcao RTP foi detectada")
        _apply_diagnosis(
            call,
            Diagnosis(
                probable_cause="RTP ausente ou sem voz em uma direcao, provavel one-way audio",
                resolution="Validar NAT, firewall, roteamento RTP, SDP anunciado e regras de midia entre as pontas.",
                severity="critical",
                category="one_way_audio",
                evidence=evidence,
                suggested_checks=["Comparar SDP x RTP real", "Conferir NAT/SBC", "Validar portas UDP RTP nos dois sentidos"],
                confidence="high",
            ),
        )
    elif missing_sdp:
        _apply_diagnosis(
            call,
            Diagnosis(
                probable_cause="SDP anunciou endpoint de midia sem RTP correspondente",
                resolution="Verificar se a captura esta no ponto correto e se o caminho RTP para o IP/porta anunciado esta liberado.",
                severity="critical",
                category="sdp_rtp_mismatch",
                evidence=[str(item.get("message")) for item in missing_sdp[:3]],
                suggested_checks=["Conferir IP c= e porta m= no SDP", "Validar NAT/SBC e firewall UDP"],
                confidence="high",
            ),
        )
    elif payload_mismatch or unexpected_rtp:
        evidence = [str(item.get("message")) for item in [*payload_mismatch, *unexpected_rtp][:4]]
        _apply_diagnosis(
            call,
            Diagnosis(
                probable_cause="Divergencia entre SDP anunciado e RTP recebido",
                resolution="Revisar negociacao SDP, payload types dinamicos, NAT/SBC e origem/destino real dos streams RTP.",
                severity="warning",
                category="sdp_rtp_mismatch",
                evidence=evidence,
                suggested_checks=["Conferir offer/answer SDP", "Verificar reescrita de SDP no SBC", "Validar payload types RTP"],
                confidence="medium",
            ),
        )

    if sequence_lost > 0 and call.status != "failed":
        _apply_diagnosis(
            call,
            Diagnosis(
                probable_cause="Gaps de sequencia RTP indicam perda de pacotes",
                resolution="Investigar perda, congestionamento, QoS, Wi-Fi/VPN, enlace ou operadora no caminho RTP.",
                severity="warning",
                category="rtp_sequence_loss",
                evidence=[
                    f"{sequence_lost} pacote(s) RTP ausente(s) estimado(s)",
                    f"{len(sequence_summary)} stream(s) com anomalia de sequencia",
                ],
                suggested_checks=["Verificar perda no caminho de rede", "Checar QoS e filas", "Comparar captura em pontos diferentes do caminho"],
                confidence="medium",
            ),
        )

    if retransmission_count > 0 and call.status == "success":
        _apply_diagnosis(
            call,
            Diagnosis(
                probable_cause="Retransmissoes SIP detectadas durante a chamada",
                resolution="Investigar perda/latencia no caminho SIP, firewall, roteamento ou resposta tardia de algum elemento.",
                severity="warning",
                category="sip_retransmissions",
                evidence=[f"{retransmission_count} retransmissao(oes) SIP detectada(s)"],
                suggested_checks=["Conferir latencia SIP", "Validar caminho entre origem, SBC/PBX e destino", "Checar perda UDP/TCP no sinalizador"],
                confidence="medium",
            ),
        )


@app.post("/api/analyze", response_model=AnalyzeResponse)
async def analyze(file: UploadFile = File(...)) -> AnalyzeResponse:
    _validate_upload(file)
    uploaded_path = await _save_upload(file)
    warnings: list[str] = []

    try:
        media, rtp_streams, rtp_error = analyze_rtp(uploaded_path)
        if rtp_error:
            warnings.append(rtp_error)

        audio_streams, audio_mix, audio_error = extract_audio_streams(uploaded_path, file.filename or uploaded_path.name)
        if audio_error:
            warnings.append(audio_error)

        calls, sip_error = analyze_sip(uploaded_path, media)
        if sip_error:
            warnings.append(sip_error)

        if not calls:
            analysis = _empty_analysis(file.filename or uploaded_path.name, warnings)
            analysis.technical["audio_streams"] = [stream.model_dump(exclude={"wav_base64"}) for stream in audio_streams]
            return analysis

        for call in calls:
            call.audio_streams = audio_streams
            call.audio_mix = audio_mix
            sdp_media = call.technical.get("sdp_media", [])
            if isinstance(sdp_media, list):
                call.rtp_legs = build_rtp_legs(sdp_media, audio_streams)
                sdp_rtp_comparison = compare_sdp_to_rtp(sdp_media, audio_streams)
                call.technical["sdp_rtp_comparison"] = sdp_rtp_comparison
            else:
                sdp_rtp_comparison = []
            sequence_summary = _rtp_sequence_summary(audio_streams)
            call.technical["rtp_sequence_analysis"] = sequence_summary
            problematic_expected_legs = [
                leg for leg in call.rtp_legs if leg.leg_id.startswith("expected-") and leg.status in {"missing", "no_audio"}
            ]
            no_audio_streams = [leg for leg in call.rtp_legs if leg.status == "no_audio"]
            if problematic_expected_legs and call.final_sip_code and 200 <= call.final_sip_code < 300:
                call.status = "failed"
                missing = [leg for leg in problematic_expected_legs if leg.status == "missing"]
                if missing:
                    cause = "Uma perna RTP esperada pelo SDP nao chegou ao PCAP"
                else:
                    cause = "Uma perna RTP recebeu apenas CN/DTMF ou sem audio de voz util"
                call.diagnosis = Diagnosis(
                    probable_cause=f"{cause}, provavel one-way audio",
                    resolution="Validar NAT, firewall, roteamento RTP, SDP anunciado e regras de midia entre as pontas.",
                    severity="critical",
                    category="one_way_audio",
                    evidence=[
                        "SIP final 2xx indica chamada estabelecida",
                        f"{len(problematic_expected_legs)} perna(s) RTP esperada(s) com problema",
                    ],
                    suggested_checks=["Comparar SDP x RTP real", "Conferir NAT/SBC", "Validar portas UDP RTP nos dois sentidos"],
                    confidence="high",
                )
                call.technical["rtp_problematic_legs"] = [leg.model_dump() for leg in problematic_expected_legs]
            elif no_audio_streams and call.final_sip_code and 200 <= call.final_sip_code < 300 and call.status == "success":
                call.status = "warning"
                call.diagnosis = Diagnosis(
                    probable_cause="Ha stream RTP com pacotes, mas sem audio de voz util",
                    resolution="Verificar se o stream e apenas comfort noise/DTMF ou se uma das pontas esta enviando midia incorreta.",
                    severity="warning",
                    category="rtp_no_voice",
                    evidence=[f"{len(no_audio_streams)} stream(s) RTP sem voz util"],
                    suggested_checks=["Conferir payload types RTP", "Validar negociacao SDP e codec"],
                    confidence="medium",
                )
                call.technical["rtp_no_audio_streams"] = [leg.model_dump() for leg in no_audio_streams]
            _enrich_technical_diagnosis(call, sdp_rtp_comparison)

        failed = sum(1 for call in calls if call.status == "failed")
        successful = sum(1 for call in calls if call.status == "success")
        response = AnalyzeResponse(
            filename=file.filename or uploaded_path.name,
            summary=Summary(total_calls=len(calls), failed_calls=failed, successful_calls=successful),
            calls=calls,
            warnings=warnings,
            technical={
                "rtp_streams": [stream.__dict__ for stream in rtp_streams],
                "audio_streams": [stream.model_dump(exclude={"wav_base64"}) for stream in audio_streams],
                "audio_mix": audio_mix.model_dump(exclude={"wav_base64"}) if audio_mix else None,
                "rtp_sequence_analysis": _rtp_sequence_summary(audio_streams),
            },
        )
        return response
    finally:
        uploaded_path.unlink(missing_ok=True)


@app.post("/api/report/markdown")
async def markdown_report(analysis: AnalyzeResponse) -> dict[str, str]:
    return {"markdown": build_markdown_report(analysis)}


@app.post("/api/report/json")
async def json_report(analysis: AnalyzeResponse) -> dict[str, str]:
    return {"json": json.dumps(analysis.model_dump(by_alias=True), ensure_ascii=False, indent=2)}
