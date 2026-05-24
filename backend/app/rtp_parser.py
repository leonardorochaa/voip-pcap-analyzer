from __future__ import annotations

import base64
import io
import re
import struct
import wave
from dataclasses import dataclass
from pathlib import Path

from .config import settings
from .models import AudioMix, AudioStream, MediaStats, RtpLeg
from .tshark import TsharkError, parse_float, parse_int, run_tshark


@dataclass
class RtpStream:
    source: str | None
    src_port: int | None
    destination: str | None
    dst_port: int | None
    packet_loss_percent: float | None
    max_jitter_ms: float | None
    raw: str


@dataclass
class RtpPacket:
    time: float
    source: str | None
    src_port: int | None
    destination: str | None
    dst_port: int | None
    ssrc: str | None
    payload_type: int | None
    sequence: int | None
    timestamp: int | None
    payload: bytes

    @property
    def stream_key(self) -> tuple[str | None, int | None, str | None, int | None, str | None]:
        return (self.source, self.src_port, self.destination, self.dst_port, self.ssrc)


STREAM_RE = re.compile(
    r"(?P<src>\d{1,3}(?:\.\d{1,3}){3})\s+"
    r"(?P<src_port>\d+)\s+"
    r"(?P<dst>\d{1,3}(?:\.\d{1,3}){3})\s+"
    r"(?P<dst_port>\d+)\s+"
    r".*",
)

PAYLOAD_CODECS = {
    0: "PCMU",
    8: "PCMA",
}

NON_AUDIO_PAYLOAD_TYPES = {13, 101}
RTP_SEQUENCE_MODULO = 65536


def parse_rtp_streams_output(output: str) -> list[RtpStream]:
    streams: list[RtpStream] = []

    for line in output.splitlines():
        if "Detected" in line or "Src IP" in line or "===" in line:
            continue
        if not re.search(r"\d{1,3}(?:\.\d{1,3}){3}", line):
            continue

        match = STREAM_RE.search(line)
        if not match:
            continue

        numbers = re.findall(r"-?\d+(?:[\.,]\d+)?%?", line)
        percentages = [parse_float(item) for item in numbers if "%" in item]
        floats = [value for value in (parse_float(item) for item in numbers) if value is not None]

        jitter = None
        lower = line.lower()
        if "jitter" in lower:
            jitter = parse_float(line[lower.find("jitter") :])
        elif len(floats) >= 2:
            jitter = floats[-2]

        loss = next((value for value in percentages if value is not None), None)

        streams.append(
            RtpStream(
                source=match.group("src"),
                src_port=int(match.group("src_port")),
                destination=match.group("dst"),
                dst_port=int(match.group("dst_port")),
                packet_loss_percent=loss,
                max_jitter_ms=jitter,
                raw=line.strip(),
            )
        )

    return streams


def analyze_rtp(pcap_path: Path) -> tuple[MediaStats, list[RtpStream], str | None]:
    try:
        output = run_tshark(pcap_path, ["-q", "-z", "rtp,streams"])
    except TsharkError as exc:
        return MediaStats(), [], str(exc)

    streams = parse_rtp_streams_output(output)
    endpoints = {(stream.source, stream.src_port, stream.destination, stream.dst_port) for stream in streams}
    directions = len(endpoints)

    losses = [stream.packet_loss_percent for stream in streams if stream.packet_loss_percent is not None]
    jitters = [stream.max_jitter_ms for stream in streams if stream.max_jitter_ms is not None]

    stats = MediaStats(
        rtp_detected=bool(streams),
        directions=min(directions, 2) if streams else 0,
        packet_loss_percent=max(losses) if losses else None,
        max_jitter_ms=max(jitters) if jitters else None,
    )
    return stats, streams, None


def _decode_mulaw_byte(value: int) -> int:
    value = (~value) & 0xFF
    sign = value & 0x80
    exponent = (value >> 4) & 0x07
    mantissa = value & 0x0F
    sample = ((mantissa << 3) + 0x84) << exponent
    sample -= 0x84
    return -sample if sign else sample


def _decode_alaw_byte(value: int) -> int:
    value ^= 0x55
    sign = value & 0x80
    exponent = (value & 0x70) >> 4
    mantissa = value & 0x0F
    if exponent == 0:
        sample = (mantissa << 4) + 8
    else:
        sample = ((mantissa << 4) + 0x108) << (exponent - 1)
    return sample if sign else -sample


def _decode_g711(payload: bytes, codec: str) -> bytes:
    if codec == "PCMU":
        samples = [_decode_mulaw_byte(byte) for byte in payload]
    elif codec == "PCMA":
        samples = [_decode_alaw_byte(byte) for byte in payload]
    else:
        samples = []
    return b"".join(struct.pack("<h", max(-32768, min(32767, sample))) for sample in samples)


def _wav_bytes(pcm: bytes, sample_rate: int = 8000) -> bytes:
    buffer = io.BytesIO()
    with wave.open(buffer, "wb") as wav:
        wav.setnchannels(1)
        wav.setsampwidth(2)
        wav.setframerate(sample_rate)
        wav.writeframes(pcm)
    return buffer.getvalue()


def _wav_base64_from_pcm(pcm: bytes) -> str:
    return base64.b64encode(_wav_bytes(pcm)).decode("ascii")


def _waveform(pcm: bytes, buckets: int = 240) -> list[float]:
    if not pcm:
        return []
    samples = struct.unpack(f"<{len(pcm) // 2}h", pcm)
    if not samples:
        return []
    bucket_size = max(1, len(samples) // buckets)
    peaks: list[float] = []
    for index in range(0, len(samples), bucket_size):
        chunk = samples[index : index + bucket_size]
        peak = max(abs(sample) for sample in chunk) / 32768
        peaks.append(round(peak, 4))
    return peaks[:buckets]


def _payload_bytes(value: str | None) -> bytes:
    if not value:
        return b""
    cleaned = value.replace(":", "").replace(" ", "").strip()
    if not cleaned:
        return b""
    try:
        return bytes.fromhex(cleaned)
    except ValueError:
        return b""


def _parse_rtp_packets(output: str) -> list[RtpPacket]:
    packets: list[RtpPacket] = []
    for line in output.splitlines():
        columns = line.split("\t")
        if len(columns) < 10:
            columns.extend([""] * (10 - len(columns)))
        time_value, src, src_port, dst, dst_port, ssrc, payload_type, sequence, timestamp, payload = columns[:10]
        payload_data = _payload_bytes(payload)
        if not payload_data:
            continue
        packets.append(
            RtpPacket(
                time=parse_float(time_value) or 0.0,
                source=src or None,
                src_port=parse_int(src_port),
                destination=dst or None,
                dst_port=parse_int(dst_port),
                ssrc=ssrc or None,
                payload_type=parse_int(payload_type),
                sequence=parse_int(sequence),
                timestamp=parse_int(timestamp),
                payload=payload_data,
            )
        )
    return packets


def _sequence_delta(previous: int, current: int) -> int:
    return (current - previous) % RTP_SEQUENCE_MODULO


def _sequence_anomalies(packets: list[RtpPacket]) -> dict[str, int | list[dict[str, int | float | None]]]:
    sequenced_packets = [packet for packet in sorted(packets, key=lambda item: item.time) if packet.sequence is not None]
    if not sequenced_packets:
        return {
            "expected_packet_count": None,
            "sequence_gap_count": 0,
            "lost_packet_count": 0,
            "duplicate_packet_count": 0,
            "out_of_order_packet_count": 0,
            "max_sequence_gap": 0,
            "gaps": [],
        }

    seen: set[int] = set()
    duplicate_count = 0
    out_of_order_count = 0
    gap_count = 0
    lost_count = 0
    max_gap = 0
    gaps: list[dict[str, int | float | None]] = []
    previous: int | None = None

    for packet in sequenced_packets:
        sequence = packet.sequence
        if sequence is None:
            continue
        if sequence in seen:
            duplicate_count += 1
        seen.add(sequence)

        if previous is None:
            previous = sequence
            continue

        delta = _sequence_delta(previous, sequence)
        if delta == 0:
            previous = sequence
            continue
        if delta > RTP_SEQUENCE_MODULO // 2:
            out_of_order_count += 1
            previous = sequence
            continue
        if delta > 1:
            missing = delta - 1
            gap_count += 1
            lost_count += missing
            max_gap = max(max_gap, missing)
            gaps.append(
                {
                    "time": round(packet.time, 3),
                    "previous_sequence": previous,
                    "current_sequence": sequence,
                    "missing_packets": missing,
                }
            )
        previous = sequence

    expected = len(sequenced_packets) + lost_count - duplicate_count
    return {
        "expected_packet_count": max(expected, len(sequenced_packets)),
        "sequence_gap_count": gap_count,
        "lost_packet_count": lost_count,
        "duplicate_packet_count": duplicate_count,
        "out_of_order_packet_count": out_of_order_count,
        "max_sequence_gap": max_gap,
        "gaps": gaps[:50],
    }


def _mix_pcm_tracks(tracks: list[tuple[float, bytes]], sample_rate: int = 8000) -> bytes:
    if not tracks:
        return b""

    first_track_time = min(start_time for start_time, pcm in tracks if pcm)
    decoded_tracks: list[tuple[int, tuple[int, ...]]] = []
    total_samples = 0
    for start_time, pcm in tracks:
        if not pcm:
            continue
        samples = struct.unpack(f"<{len(pcm) // 2}h", pcm)
        offset = max(0, int((start_time - first_track_time) * sample_rate))
        decoded_tracks.append((offset, samples))
        total_samples = max(total_samples, offset + len(samples))

    if total_samples == 0:
        return b""

    mix = [0] * total_samples
    contributors = [0] * total_samples
    for offset, samples in decoded_tracks:
        for index, sample in enumerate(samples):
            position = offset + index
            mix[position] += sample
            contributors[position] += 1

    normalized = []
    for value, count in zip(mix, contributors):
        sample = int(value / count) if count else 0
        normalized.append(max(-32768, min(32767, sample)))
    return b"".join(struct.pack("<h", sample) for sample in normalized)


def _build_audio_mix(filename: str, tracks: list[tuple[float, bytes]]) -> AudioMix | None:
    pcm = _mix_pcm_tracks(tracks)
    if not pcm:
        return None
    return AudioMix(
        duration_seconds=round(len(pcm) / 2 / 8000, 3),
        wav_base64=_wav_base64_from_pcm(pcm),
        wav_filename=f"{Path(filename).stem}-call-audio.wav",
        waveform=_waveform(pcm, buckets=360),
    )


def extract_audio_streams(pcap_path: Path, filename: str | None = None) -> tuple[list[AudioStream], AudioMix | None, str | None]:
    args = [
        "-Y",
        "rtp && rtp.payload",
        "-T",
        "fields",
        "-E",
        "separator=\t",
        "-e",
        "frame.time_relative",
        "-e",
        "ip.src",
        "-e",
        "udp.srcport",
        "-e",
        "ip.dst",
        "-e",
        "udp.dstport",
        "-e",
        "rtp.ssrc",
        "-e",
        "rtp.p_type",
        "-e",
        "rtp.seq",
        "-e",
        "rtp.timestamp",
        "-e",
        "rtp.payload",
    ]
    try:
        output = run_tshark(pcap_path, args)
    except TsharkError as exc:
        return [], None, str(exc)

    packets = _parse_rtp_packets(output)
    grouped: dict[tuple[str | None, int | None, str | None, int | None, str | None], list[RtpPacket]] = {}
    for packet in packets:
        grouped.setdefault(packet.stream_key, []).append(packet)

    audio_streams: list[AudioStream] = []
    mix_tracks: list[tuple[float, bytes]] = []
    for index, (key, stream_packets) in enumerate(grouped.items(), start=1):
        if index > settings.audio_max_streams:
            break

        stream_packets.sort(key=lambda packet: (packet.sequence if packet.sequence is not None else 0, packet.time))
        first = min(stream_packets, key=lambda packet: packet.time)
        last = max(stream_packets, key=lambda packet: packet.time)
        sequence_stats = _sequence_anomalies(stream_packets)
        source, src_port, destination, dst_port, ssrc = key
        payload_types = sorted({packet.payload_type for packet in stream_packets if packet.payload_type is not None})
        playable_payload_type = next((payload for payload in payload_types if payload in PAYLOAD_CODECS), None)
        payload_type = playable_payload_type if playable_payload_type is not None else next(iter(payload_types), None)
        codec = PAYLOAD_CODECS.get(playable_payload_type) if playable_payload_type is not None else None
        voice_packets = [packet for packet in stream_packets if packet.payload_type == playable_payload_type] if playable_payload_type is not None else []
        duration = max(last.time - first.time, 0)

        base = AudioStream(
            stream_id=f"rtp-{index}",
            source=source,
            source_port=src_port,
            destination=destination,
            destination_port=dst_port,
            ssrc=ssrc,
            payload_type=payload_type,
            payload_types=payload_types,
            codec=codec,
            packet_count=len(stream_packets),
            voice_packet_count=len(voice_packets),
            expected_packet_count=sequence_stats["expected_packet_count"],  # type: ignore[arg-type]
            sequence_gap_count=int(sequence_stats["sequence_gap_count"]),
            lost_packet_count=int(sequence_stats["lost_packet_count"]),
            duplicate_packet_count=int(sequence_stats["duplicate_packet_count"]),
            out_of_order_packet_count=int(sequence_stats["out_of_order_packet_count"]),
            max_sequence_gap=int(sequence_stats["max_sequence_gap"]),
            rtp_sequence_gaps=sequence_stats["gaps"],  # type: ignore[arg-type]
            duration_seconds=round(duration, 3),
            start_time=round(first.time, 3),
            end_time=round(last.time, 3),
            wav_filename=f"rtp-{index}-{source or 'src'}-{src_port or 0}.wav",
        )

        if not codec:
            if payload_types and all(payload in NON_AUDIO_PAYLOAD_TYPES for payload in payload_types):
                base.unsupported_reason = "Stream contem apenas CN/DTMF, sem audio de voz"
            else:
                base.unsupported_reason = f"Payload RTP {payload_type} sem decoder de audio neste MVP"
            audio_streams.append(base)
            continue

        pcm_parts: list[bytes] = []
        max_samples = settings.audio_max_seconds * 8000
        decoded_samples = 0
        for packet in stream_packets:
            if packet.payload_type != playable_payload_type:
                continue
            decoded = _decode_g711(packet.payload, codec)
            samples = len(decoded) // 2
            if decoded_samples + samples > max_samples:
                remaining = max_samples - decoded_samples
                if remaining > 0:
                    pcm_parts.append(decoded[: remaining * 2])
                break
            pcm_parts.append(decoded)
            decoded_samples += samples

        pcm = b"".join(pcm_parts)
        if not pcm:
            base.unsupported_reason = "Stream sem pacotes de voz decodificaveis"
            audio_streams.append(base)
            continue

        base.extractable = True
        base.wav_base64 = _wav_base64_from_pcm(pcm)
        base.waveform = _waveform(pcm)
        base.duration_seconds = round(len(pcm) / 2 / 8000, 3) if pcm else base.duration_seconds
        audio_streams.append(base)
        mix_tracks.append((first.time, pcm))

    return audio_streams, _build_audio_mix(filename or pcap_path.name, mix_tracks), None


def _parse_port(value: object) -> int | None:
    if value is None:
        return None
    return parse_int(str(value))


def _formats_from_media(media: dict[str, object]) -> set[int]:
    formats = media.get("formats")
    values: list[str] = []
    if isinstance(formats, list):
        values = [str(item) for item in formats]
    elif formats:
        values = [str(formats)]

    payloads: set[int] = set()
    for value in values:
        for item in re.findall(r"\b\d+\b", value):
            parsed = parse_int(item)
            if parsed is not None:
                payloads.add(parsed)
    return payloads


def _sdp_endpoints(sdp_media: list[dict[str, object]]) -> list[dict[str, object]]:
    endpoints: list[dict[str, object]] = []
    seen: set[tuple[str | None, int | None]] = set()
    for media in sdp_media:
        ip = str(media.get("sdp_ip")) if media.get("sdp_ip") else None
        ports = media.get("sdp_ports")
        if not isinstance(ports, list):
            ports = []
        payload_types = sorted(_formats_from_media(media))
        for port_value in ports:
            port = _parse_port(port_value)
            key = (ip, port)
            if not ip or not port or key in seen:
                continue
            seen.add(key)
            endpoints.append(
                {
                    "ip": ip,
                    "port": port,
                    "payload_types": payload_types,
                    "source": media.get("source"),
                    "sdp_time": media.get("time"),
                    "method": media.get("method"),
                    "status_code": media.get("status_code"),
                }
            )
    return endpoints


def compare_sdp_to_rtp(sdp_media: list[dict[str, object]], audio_streams: list[AudioStream]) -> list[dict[str, object]]:
    endpoints = _sdp_endpoints(sdp_media)
    comparisons: list[dict[str, object]] = []
    matched_stream_ids: set[str] = set()

    for endpoint in endpoints:
        ip = endpoint["ip"]
        port = endpoint["port"]
        matches = [
            stream
            for stream in audio_streams
            if stream.destination == ip and stream.destination_port == port
        ]
        if not matches:
            comparisons.append(
                {
                    "type": "missing_rtp",
                    "severity": "critical",
                    "endpoint": endpoint,
                    "message": f"SDP anunciou RTP em {ip}:{port}, mas nenhum stream RTP chegou nesse destino",
                }
            )
            continue

        for stream in matches:
            matched_stream_ids.add(stream.stream_id)
            announced_payloads = set(endpoint.get("payload_types") or [])
            actual_payloads = set(stream.payload_types)
            unexpected_payloads = sorted(actual_payloads - announced_payloads) if announced_payloads else []
            if unexpected_payloads:
                comparisons.append(
                    {
                        "type": "payload_mismatch",
                        "severity": "warning",
                        "endpoint": endpoint,
                        "stream_id": stream.stream_id,
                        "actual_payload_types": stream.payload_types,
                        "unexpected_payload_types": unexpected_payloads,
                        "message": f"RTP em {ip}:{port} usou payload(s) {unexpected_payloads} fora do anunciado no SDP",
                    }
                )
            elif stream.voice_packet_count == 0:
                comparisons.append(
                    {
                        "type": "no_voice_payload",
                        "severity": "warning",
                        "endpoint": endpoint,
                        "stream_id": stream.stream_id,
                        "actual_payload_types": stream.payload_types,
                        "message": f"RTP em {ip}:{port} chegou, mas sem pacotes de voz util",
                    }
                )
            else:
                comparisons.append(
                    {
                        "type": "matched",
                        "severity": "info",
                        "endpoint": endpoint,
                        "stream_id": stream.stream_id,
                        "actual_payload_types": stream.payload_types,
                        "message": f"RTP recebido em {ip}:{port} compativel com endpoint anunciado no SDP",
                    }
                )

    announced_destinations = {(endpoint["ip"], endpoint["port"]) for endpoint in endpoints}
    for stream in audio_streams:
        if stream.stream_id in matched_stream_ids:
            continue
        destination = (stream.destination, stream.destination_port)
        if announced_destinations and destination not in announced_destinations:
            comparisons.append(
                {
                    "type": "unexpected_rtp",
                    "severity": "warning",
                    "stream_id": stream.stream_id,
                    "source": stream.source,
                    "source_port": stream.source_port,
                    "destination": stream.destination,
                    "destination_port": stream.destination_port,
                    "actual_payload_types": stream.payload_types,
                    "message": f"RTP recebido em {stream.destination}:{stream.destination_port}, mas esse destino nao aparece no SDP",
                }
            )

    return comparisons


def _actual_leg_from_stream(stream: AudioStream, index: int) -> RtpLeg:
    payload_types = stream.payload_types or ([stream.payload_type] if stream.payload_type is not None else [])
    codecs = [stream.codec] if stream.codec else []
    ssrc = [stream.ssrc] if stream.ssrc else []
    status = "received" if stream.voice_packet_count > 0 and stream.extractable else "no_audio"
    note = "RTP com audio de voz detectado no PCAP" if status == "received" else "RTP recebido, mas sem audio de voz util (CN/DTMF ou codec nao decodificavel)"
    return RtpLeg(
        leg_id=f"actual-{index}",
        status=status,
        source=stream.source,
        source_port=stream.source_port,
        destination=stream.destination,
        destination_port=stream.destination_port,
        packet_count=stream.packet_count,
        voice_packet_count=stream.voice_packet_count,
        payload_types=payload_types,
        codecs=codecs,
        ssrc=ssrc,
        start_time=stream.start_time,
        end_time=stream.end_time,
        duration_seconds=stream.duration_seconds,
        audio_stream_id=stream.stream_id,
        note=note,
    )


def _matches_expected(stream: AudioStream, source: str | None, destination: str | None, destination_port: int | None) -> bool:
    if destination and stream.destination != destination:
        return False
    if destination_port and stream.destination_port != destination_port:
        return False
    if source and stream.source and stream.source != source:
        return False
    return True


def build_rtp_legs(sdp_media: list[dict[str, object]], audio_streams: list[AudioStream]) -> list[RtpLeg]:
    endpoints: list[tuple[str | None, int | None]] = []
    for media in sdp_media:
        ip = media.get("sdp_ip")
        ports = media.get("sdp_ports")
        if not isinstance(ports, list):
            ports = []
        for port_value in ports:
            endpoint = (str(ip) if ip else None, _parse_port(port_value))
            if endpoint[0] and endpoint[1] and endpoint not in endpoints:
                endpoints.append(endpoint)

    legs: list[RtpLeg] = []
    used_stream_ids: set[str] = set()
    if len(endpoints) >= 2:
        expected_pairs = [(endpoints[0], endpoints[1]), (endpoints[1], endpoints[0])]
        for index, ((src_ip, src_port), (dst_ip, dst_port)) in enumerate(expected_pairs, start=1):
            candidates = sorted(
                [
                    stream
                    for stream in audio_streams
                    if _matches_expected(stream, src_ip, dst_ip, dst_port) or _matches_expected(stream, None, dst_ip, dst_port)
                ],
                key=lambda stream: (stream.voice_packet_count, stream.packet_count),
                reverse=True,
            )
            match = candidates[0] if candidates else None
            if match:
                used_stream_ids.add(match.stream_id)
                leg = _actual_leg_from_stream(match, index)
                leg.leg_id = f"expected-{index}"
                leg.source = match.source or src_ip
                leg.source_port = match.source_port or src_port
                leg.destination = match.destination or dst_ip
                leg.destination_port = match.destination_port or dst_port
                leg.note = "Perna RTP esperada pelo SDP e recebida no PCAP"
                if leg.status == "no_audio":
                    leg.note = "Perna RTP esperada pelo SDP recebeu pacotes, mas sem audio de voz util"
                legs.append(leg)
            else:
                legs.append(
                    RtpLeg(
                        leg_id=f"expected-{index}",
                        status="missing",
                        source=src_ip,
                        source_port=src_port,
                        destination=dst_ip,
                        destination_port=dst_port,
                        note="Perna esperada pelo SDP, mas sem RTP correspondente no PCAP",
                    )
                )

    for index, stream in enumerate(audio_streams, start=1):
        if stream.stream_id in used_stream_ids:
            continue
        legs.append(_actual_leg_from_stream(stream, len(legs) + index))

    if not legs and endpoints:
        for index, (ip, port) in enumerate(endpoints, start=1):
            legs.append(
                RtpLeg(
                    leg_id=f"advertised-{index}",
                    status="unknown",
                    destination=ip,
                    destination_port=port,
                    note="Endereco de midia anunciado no SDP, sem par suficiente para inferir direcao",
                )
            )

    return legs
