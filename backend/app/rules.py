from __future__ import annotations

from .models import Diagnosis, MediaStats, SipTimelineEvent


SIP_RULES: dict[int, tuple[str, str, str]] = {
    403: (
        "Chamada rejeitada por autorizacao ou politica",
        "Revisar credenciais, ACL, trunk ou IP autorizado.",
        "critical",
    ),
    404: (
        "Destino inexistente",
        "Validar numero discado, plano de discagem e roteamento.",
        "critical",
    ),
    408: (
        "Timeout SIP",
        "Investigar rota, firewall, NAT e disponibilidade do destino.",
        "critical",
    ),
    480: (
        "Destino temporariamente indisponivel",
        "Validar registro do ramal, encaminhamento e disponibilidade do destino.",
        "warning",
    ),
    486: (
        "Destino ocupado",
        "Confirmar estado do destino e politicas de ocupado/encaminhamento.",
        "warning",
    ),
    488: (
        "Codec ou SDP incompativel",
        "Revisar codecs permitidos, payloads RTP e parametros SDP entre as pontas.",
        "critical",
    ),
    415: (
        "Midia ou SDP nao suportado",
        "Revisar codecs, tipo de midia e negociacao SDP.",
        "critical",
    ),
    503: (
        "Falha temporaria em operadora, SBC ou PBX",
        "Verificar saude do trunk, SBC/PBX, rota de saida e resposta da operadora.",
        "critical",
    ),
}


def classify_call(final_sip_code: int | None, media: MediaStats, timeline: list[SipTimelineEvent]) -> Diagnosis:
    if final_sip_code in SIP_RULES:
        cause, resolution, severity = SIP_RULES[final_sip_code]
        return Diagnosis(
            probable_cause=cause,
            resolution=resolution,
            severity=severity,  # type: ignore[arg-type]
            category="sip_failure",
            evidence=[f"Resposta SIP final {final_sip_code}"],
            suggested_checks=["Revisar o elemento que enviou a resposta final", "Conferir rota, trunk, plano de discagem e politica SIP"],
            confidence="high",
        )

    has_200 = any(event.status_code == 200 for event in timeline)
    has_ack = any(event.method == "ACK" for event in timeline)

    if has_200 and has_ack and not media.rtp_detected:
        return Diagnosis(
            probable_cause="Sem RTP apos 200 OK",
            resolution="Investigar NAT/firewall, IP/porta no SDP e regras de midia entre as pontas.",
            severity="critical",
            category="no_way_audio",
            evidence=["Chamada recebeu 200 OK e ACK", "Nenhum stream RTP foi detectado na captura"],
            suggested_checks=["Validar IP/porta c= e m= no SDP", "Conferir bloqueio UDP/firewall/NAT no caminho RTP"],
            confidence="high",
        )

    if media.rtp_detected and media.directions == 1:
        return Diagnosis(
            probable_cause="RTP em apenas uma direcao, provavel one-way audio",
            resolution="Validar NAT, firewall, roteamento RTP e endereco anunciado no SDP.",
            severity="critical",
            category="one_way_audio",
            evidence=["Apenas uma direcao RTP foi detectada"],
            suggested_checks=["Conferir NAT/SBC", "Validar regras UDP das portas RTP", "Comparar SDP anunciado com o RTP recebido"],
            confidence="high",
        )

    if media.max_jitter_ms is not None and media.max_jitter_ms >= 30:
        return Diagnosis(
            probable_cause="Jitter RTP alto",
            resolution="Investigar rede, QoS, filas, perda em enlace e variacao de latencia.",
            severity="warning",
            category="rtp_quality",
            evidence=[f"Jitter maximo RTP {media.max_jitter_ms:.2f} ms"],
            suggested_checks=["Verificar QoS", "Conferir congestionamento, VPN, Wi-Fi e enlaces intermediarios"],
            confidence="medium",
        )

    if media.packet_loss_percent is not None and media.packet_loss_percent >= 3:
        return Diagnosis(
            probable_cause="Perda RTP alta",
            resolution="Investigar congestionamento, link, QoS, Wi-Fi/VPN e operadora.",
            severity="warning",
            category="rtp_quality",
            evidence=[f"Perda RTP {media.packet_loss_percent:.2f}%"],
            suggested_checks=["Verificar perda no caminho de rede", "Conferir filas, QoS e operadora"],
            confidence="medium",
        )

    if final_sip_code is None:
        return Diagnosis(
            probable_cause="Nao foi possivel determinar o codigo SIP final",
            resolution="Verificar se o PCAP contem a sinalizacao completa da chamada.",
            severity="warning",
            category="incomplete_capture",
            evidence=["Nenhuma resposta SIP final foi identificada"],
            suggested_checks=["Confirmar se a captura contem inicio e fim da chamada"],
            confidence="medium",
        )

    if 200 <= final_sip_code < 300:
        return Diagnosis(
            probable_cause="Chamada completada com RTP bidirecional" if media.directions >= 2 else "Chamada completada",
            resolution="Nenhuma acao necessaria." if media.directions >= 2 else "Validar midia RTP se houver queixa de audio.",
            severity="info" if media.directions >= 2 else "warning",
            category="completed" if media.directions >= 2 else "completed_media_uncertain",
            evidence=[f"Resposta SIP final {final_sip_code}", f"Direcoes RTP detectadas: {media.directions}"],
            suggested_checks=[] if media.directions >= 2 else ["Comparar a midia RTP com o SDP se houver queixa de audio"],
            confidence="medium",
        )

    if final_sip_code >= 400:
        return Diagnosis(
            probable_cause=f"Falha SIP {final_sip_code}",
            resolution="Revisar a resposta SIP final, o fluxo de sinalizacao e os elementos envolvidos.",
            severity="critical",
            category="sip_failure",
            evidence=[f"Resposta SIP final {final_sip_code}"],
            suggested_checks=["Identificar o IP que enviou a resposta final", "Conferir CSeq, Via e rota SIP"],
            confidence="high",
        )

    return Diagnosis(
        probable_cause="Chamada em estado indeterminado",
        resolution="Validar se a captura contem o inicio e o fim da chamada.",
        severity="warning",
        category="indeterminate",
        evidence=["Fluxo SIP insuficiente para uma conclusao forte"],
        suggested_checks=["Confirmar ponto de captura e filtros usados"],
        confidence="low",
    )
