from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from .models import CallAnalysis, MediaStats, SipTimelineEvent
from .rules import classify_call
from .tshark import TsharkError, parse_float, parse_int, run_tshark


STATIC_PAYLOAD_CODECS = {
    "0": "PCMU",
    "3": "GSM",
    "4": "G723",
    "8": "PCMA",
    "9": "G722",
    "18": "G729",
    "101": "telephone-event",
}

BASE_SIP_FIELDS = [
    "frame.time_relative",
    "ip.src",
    "ip.dst",
    "sip.Call-ID",
    "sip.Method",
    "sip.Status-Code",
    "sip.Reason-Phrase",
    "sip.CSeq.method",
    "sip.from.user",
    "sip.from.host",
    "sip.to.user",
    "sip.to.host",
    "sdp.connection_info.address",
    "sdp.media.port",
    "sdp.media.format",
    "sdp.media_attr",
]

SIP_FIELDS = BASE_SIP_FIELDS[:7] + ["sip.CSeq.seq", "sip.CSeq.method", "sip.Via.branch"] + BASE_SIP_FIELDS[8:]


@dataclass
class SipPacket:
    time: float
    source: str | None
    destination: str | None
    call_id: str
    method: str | None
    status_code: int | None
    reason: str | None
    cseq_seq: int | None
    cseq_method: str | None
    via_branch: str | None
    from_user: str | None
    from_host: str | None
    to_user: str | None
    to_host: str | None
    sdp_ip: str | None
    sdp_ports: list[str] = field(default_factory=list)
    sdp_formats: list[str] = field(default_factory=list)
    sdp_attrs: list[str] = field(default_factory=list)


def _split_multi(value: str | None) -> list[str]:
    if not value:
        return []
    parts: list[str] = []
    for chunk in value.replace(";", ",").split(","):
        item = chunk.strip()
        if item:
            parts.append(item)
    return parts


def _endpoint(user: str | None, host: str | None) -> str | None:
    if user and host:
        return f"{user}@{host}"
    return user or host


def _codecs_from_packet(packet: SipPacket) -> list[str]:
    codecs: list[str] = []
    for attr in packet.sdp_attrs:
        lower = attr.lower()
        if "rtpmap" not in lower:
            continue
        # Examples: a=rtpmap:0 PCMU/8000 or rtpmap:8 PCMA/8000
        if " " in attr:
            payload_name = attr.split(" ", 1)[1].split("/", 1)[0].strip()
            if payload_name and payload_name not in codecs:
                codecs.append(payload_name)

    for fmt in packet.sdp_formats:
        for payload in fmt.split():
            codec = STATIC_PAYLOAD_CODECS.get(payload.strip())
            if codec and codec not in codecs:
                codecs.append(codec)
    return codecs


def _parse_sip_rows(output: str, fields: list[str]) -> list[SipPacket]:
    packets: list[SipPacket] = []
    for line in output.splitlines():
        columns = line.split("\t")
        if len(columns) < len(fields):
            columns.extend([""] * (len(fields) - len(columns)))
        row = dict(zip(fields, columns))

        time_value = row.get("frame.time_relative")
        src = row.get("ip.src")
        dst = row.get("ip.dst")
        call_id = row.get("sip.Call-ID")
        method = row.get("sip.Method")
        status_code = row.get("sip.Status-Code")
        reason = row.get("sip.Reason-Phrase")
        cseq_seq = row.get("sip.CSeq.seq")
        cseq_method = row.get("sip.CSeq.method")
        via_branch = row.get("sip.Via.branch")
        from_user = row.get("sip.from.user")
        from_host = row.get("sip.from.host")
        to_user = row.get("sip.to.user")
        to_host = row.get("sip.to.host")
        sdp_ip = row.get("sdp.connection_info.address")
        sdp_ports = row.get("sdp.media.port")
        sdp_formats = row.get("sdp.media.format")
        sdp_attrs = row.get("sdp.media_attr")

        call_id = call_id.strip()
        if not call_id:
            continue

        packets.append(
            SipPacket(
                time=parse_float(time_value) or 0.0,
                source=src.strip() or None,
                destination=dst.strip() or None,
                call_id=call_id,
                method=(method or cseq_method).strip() or None,
                status_code=parse_int(status_code),
                reason=reason.strip() or None,
                cseq_seq=parse_int(cseq_seq),
                cseq_method=cseq_method.strip() or None,
                via_branch=via_branch.strip() or None,
                from_user=from_user.strip() or None,
                from_host=from_host.strip() or None,
                to_user=to_user.strip() or None,
                to_host=to_host.strip() or None,
                sdp_ip=sdp_ip.strip() or None,
                sdp_ports=_split_multi(sdp_ports),
                sdp_formats=_split_multi(sdp_formats),
                sdp_attrs=_split_multi(sdp_attrs),
            )
        )
    return packets


def _timeline_event(packet: SipPacket, first_time: float) -> SipTimelineEvent:
    method = packet.method
    if packet.status_code is not None and packet.cseq_method:
        method = packet.cseq_method

    return SipTimelineEvent(
        time=round(packet.time - first_time, 3),
        source=packet.source,
        destination=packet.destination,
        method=method,
        status_code=packet.status_code,
        reason=packet.reason,
    )


def _ended_by(packets: list[SipPacket]) -> str | None:
    for packet in reversed(packets):
        if packet.method in {"BYE", "CANCEL"}:
            return packet.source
    return None


def _sip_label(packet: SipPacket) -> str:
    if packet.status_code is not None:
        label = str(packet.status_code)
        if packet.reason:
            label = f"{label} {packet.reason}"
        if packet.cseq_method:
            label = f"{label} ({packet.cseq_method})"
        return label
    return packet.method or packet.cseq_method or "SIP"


def _retransmission_key(packet: SipPacket) -> tuple[object, ...]:
    transaction_id = packet.via_branch or packet.cseq_seq or packet.time
    return (
        packet.call_id,
        packet.source,
        packet.destination,
        packet.method or packet.cseq_method,
        packet.status_code,
        packet.cseq_seq,
        packet.cseq_method,
        transaction_id,
    )


def _detect_retransmissions(packets: list[SipPacket], first_time: float) -> list[dict[str, object]]:
    grouped: dict[tuple[object, ...], list[SipPacket]] = {}
    for packet in packets:
        if not (packet.method or packet.cseq_method or packet.status_code):
            continue
        grouped.setdefault(_retransmission_key(packet), []).append(packet)

    retransmissions: list[dict[str, object]] = []
    for items in grouped.values():
        if len(items) < 2:
            continue
        items.sort(key=lambda item: item.time)
        first = items[0]
        retransmissions.append(
            {
                "event": _sip_label(first),
                "source": first.source,
                "destination": first.destination,
                "cseq": first.cseq_seq,
                "cseq_method": first.cseq_method,
                "via_branch": first.via_branch,
                "first_seen": round(first.time - first_time, 3),
                "last_seen": round(items[-1].time - first_time, 3),
                "count": len(items),
                "retransmission_count": len(items) - 1,
                "intervals_ms": [
                    round((items[index].time - items[index - 1].time) * 1000, 1)
                    for index in range(1, len(items))
                ],
            }
        )
    return retransmissions


def build_calls(packets: list[SipPacket], media: MediaStats) -> list[CallAnalysis]:
    grouped: dict[str, list[SipPacket]] = {}
    for packet in packets:
        grouped.setdefault(packet.call_id, []).append(packet)

    calls: list[CallAnalysis] = []
    for call_id, call_packets in grouped.items():
        call_packets.sort(key=lambda item: item.time)
        first_time = call_packets[0].time
        last_time = call_packets[-1].time
        timeline = [_timeline_event(packet, first_time) for packet in call_packets]

        final_response = next((packet for packet in reversed(call_packets) if packet.status_code is not None), None)
        final_code = final_response.status_code if final_response else None
        final_reason = final_response.reason if final_response else None

        invite = next((packet for packet in call_packets if packet.method == "INVITE"), call_packets[0])
        codecs: list[str] = []
        sdp_media: list[dict[str, object]] = []
        for packet in call_packets:
            for codec in _codecs_from_packet(packet):
                if codec not in codecs:
                    codecs.append(codec)
            if packet.sdp_ip or packet.sdp_ports:
                sdp_media.append(
                    {
                        "time": round(packet.time - first_time, 3),
                        "source": packet.source,
                        "destination": packet.destination,
                        "sdp_ip": packet.sdp_ip,
                        "sdp_ports": packet.sdp_ports,
                        "formats": packet.sdp_formats,
                        "attrs": packet.sdp_attrs,
                        "method": packet.method,
                        "status_code": packet.status_code,
                    }
                )

        diagnosis = classify_call(final_code, media, timeline)
        status = "warning"
        if diagnosis.severity == "critical" or (final_code is not None and final_code >= 400):
            status = "failed"
        elif diagnosis.severity == "info":
            status = "success"

        calls.append(
            CallAnalysis(
                call_id=call_id,
                status=status,  # type: ignore[arg-type]
                from_=_endpoint(invite.from_user, invite.from_host),
                to=_endpoint(invite.to_user, invite.to_host),
                final_sip_code=final_code,
                final_reason=final_reason,
                duration_seconds=round(max(last_time - first_time, 0), 3),
                codec=codecs,
                media=media,
                sip_timeline=timeline,
                diagnosis=diagnosis,
                ended_by=_ended_by(call_packets),
                technical={
                    "sdp_media": sdp_media,
                    "sip_retransmissions": _detect_retransmissions(call_packets, first_time),
                },
            )
        )

    return calls


def analyze_sip(pcap_path: Path, media: MediaStats) -> tuple[list[CallAnalysis], str | None]:
    args = [
        "-Y",
        "sip",
        "-T",
        "fields",
        "-E",
        "separator=\t",
        "-E",
        "occurrence=a",
        "-E",
        "aggregator=,",
    ]
    fields = SIP_FIELDS
    for field_name in fields:
        args.extend(["-e", field_name])

    try:
        output = run_tshark(pcap_path, args)
    except TsharkError as exc:
        args = [
            "-Y",
            "sip",
            "-T",
            "fields",
            "-E",
            "separator=\t",
            "-E",
            "occurrence=a",
            "-E",
            "aggregator=,",
        ]
        fields = BASE_SIP_FIELDS
        for field_name in fields:
            args.extend(["-e", field_name])
        try:
            output = run_tshark(pcap_path, args)
        except TsharkError:
            return [], str(exc)

    packets = _parse_sip_rows(output, fields)
    if not packets:
        return [], None

    return build_calls(packets, media), None
