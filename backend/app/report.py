from __future__ import annotations

from .models import AnalyzeResponse


def build_markdown_report(analysis: AnalyzeResponse) -> str:
    lines = [
        f"# Relatorio VoIP - {analysis.filename}",
        "",
        "## Resumo",
        f"- Total de chamadas: {analysis.summary.total_calls}",
        f"- Chamadas com sucesso: {analysis.summary.successful_calls}",
        f"- Chamadas com falha: {analysis.summary.failed_calls}",
        "",
    ]

    for index, call in enumerate(analysis.calls, start=1):
        lines.extend(
            [
                f"## Chamada {index}",
                f"- Call-ID: {call.call_id}",
                f"- Status: {call.status}",
                f"- Origem: {call.from_ or '-'}",
                f"- Destino: {call.to or '-'}",
                f"- Codigo SIP final: {call.final_sip_code or '-'} {call.final_reason or ''}".rstrip(),
                f"- Duracao estimada: {call.duration_seconds if call.duration_seconds is not None else '-'}s",
                f"- Codec: {', '.join(call.codec) if call.codec else '-'}",
                f"- RTP detectado: {'sim' if call.media.rtp_detected else 'nao'}",
                f"- Direcoes RTP: {call.media.directions}",
                f"- Perda RTP: {call.media.packet_loss_percent if call.media.packet_loss_percent is not None else '-'}%",
                f"- Jitter maximo: {call.media.max_jitter_ms if call.media.max_jitter_ms is not None else '-'} ms",
                "",
                "### Diagnostico",
                call.diagnosis.probable_cause,
                "",
                "### Evidencias tecnicas",
                *(f"- {item}" for item in call.diagnosis.evidence),
                *(["- Sem evidencias estruturadas adicionais."] if not call.diagnosis.evidence else []),
                "",
                "### Resolucao sugerida",
                call.diagnosis.resolution,
                "",
                "### Comparacao SDP x RTP",
            ]
        )
        sdp_rtp = call.technical.get("sdp_rtp_comparison", [])
        if isinstance(sdp_rtp, list) and sdp_rtp:
            for item in sdp_rtp:
                if isinstance(item, dict):
                    lines.append(f"- [{item.get('severity', '-')}] {item.get('message', '-')}")
        else:
            lines.append("- Sem comparacao SDP x RTP disponivel.")
        lines.extend(
            [
                "",
                "### Retransmissoes SIP",
            ]
        )
        retransmissions = call.technical.get("sip_retransmissions", [])
        if isinstance(retransmissions, list) and retransmissions:
            for item in retransmissions:
                if isinstance(item, dict):
                    lines.append(
                        f"- {item.get('event', 'SIP')} {item.get('source', '-')} -> {item.get('destination', '-')}: "
                        f"{item.get('retransmission_count', 0)} retransmissao(oes), intervalos {item.get('intervals_ms', [])} ms"
                    )
        else:
            lines.append("- Nenhuma retransmissao SIP detectada.")
        lines.extend(
            [
                "",
                "### Gaps de sequencia RTP",
            ]
        )
        sequence_analysis = call.technical.get("rtp_sequence_analysis", [])
        if isinstance(sequence_analysis, list) and sequence_analysis:
            for item in sequence_analysis:
                if isinstance(item, dict):
                    lines.append(
                        f"- {item.get('stream_id', '-')}: {item.get('lost_packet_count', 0)} pacote(s) estimado(s) ausente(s), "
                        f"{item.get('sequence_gap_count', 0)} gap(s), {item.get('duplicate_packet_count', 0)} duplicado(s), "
                        f"{item.get('out_of_order_packet_count', 0)} fora de ordem"
                    )
        else:
            lines.append("- Nenhum gap de sequencia RTP detectado.")
        lines.extend(
            [
                "",
                "### Timeline SIP",
            ]
        )
        for event in call.sip_timeline:
            label = event.method or ""
            if event.status_code:
                label = f"{event.status_code} {event.reason or ''}".strip()
            lines.append(f"- {event.time:.3f}s {event.source or '-'} -> {event.destination or '-'}: {label}")
        lines.append("")

    return "\n".join(lines)
