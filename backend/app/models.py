from typing import Any, Literal

from pydantic import BaseModel, Field


CallStatus = Literal["success", "failed", "warning"]
Severity = Literal["info", "warning", "critical"]
RtpLegStatus = Literal["received", "missing", "no_audio", "unknown"]


class MediaStats(BaseModel):
    rtp_detected: bool = False
    directions: int = 0
    packet_loss_percent: float | None = None
    max_jitter_ms: float | None = None
    sequence_gap_count: int = 0
    duplicate_packet_count: int = 0
    out_of_order_packet_count: int = 0


class AudioStream(BaseModel):
    stream_id: str
    source: str | None = None
    source_port: int | None = None
    destination: str | None = None
    destination_port: int | None = None
    ssrc: str | None = None
    payload_type: int | None = None
    payload_types: list[int] = Field(default_factory=list)
    codec: str | None = None
    sample_rate_hz: int = 8000
    packet_count: int = 0
    voice_packet_count: int = 0
    expected_packet_count: int | None = None
    sequence_gap_count: int = 0
    lost_packet_count: int = 0
    duplicate_packet_count: int = 0
    out_of_order_packet_count: int = 0
    max_sequence_gap: int = 0
    rtp_sequence_gaps: list[dict[str, Any]] = Field(default_factory=list)
    duration_seconds: float | None = None
    start_time: float | None = None
    end_time: float | None = None
    extractable: bool = False
    unsupported_reason: str | None = None
    wav_base64: str | None = None
    wav_filename: str | None = None
    waveform: list[float] = Field(default_factory=list)


class AudioMix(BaseModel):
    stream_id: str = "call-mix"
    codec: str = "PCM WAV"
    sample_rate_hz: int = 8000
    duration_seconds: float | None = None
    wav_base64: str | None = None
    wav_filename: str | None = None
    waveform: list[float] = Field(default_factory=list)


class RtpLeg(BaseModel):
    leg_id: str
    status: RtpLegStatus
    source: str | None = None
    source_port: int | None = None
    destination: str | None = None
    destination_port: int | None = None
    packet_count: int = 0
    voice_packet_count: int = 0
    payload_types: list[int] = Field(default_factory=list)
    codecs: list[str] = Field(default_factory=list)
    ssrc: list[str] = Field(default_factory=list)
    start_time: float | None = None
    end_time: float | None = None
    duration_seconds: float | None = None
    audio_stream_id: str | None = None
    note: str | None = None


class SipTimelineEvent(BaseModel):
    time: float
    source: str | None = None
    destination: str | None = None
    method: str | None = None
    status_code: int | None = None
    reason: str | None = None


class Diagnosis(BaseModel):
    probable_cause: str
    resolution: str
    severity: Severity
    category: str | None = None
    evidence: list[str] = Field(default_factory=list)
    suggested_checks: list[str] = Field(default_factory=list)
    confidence: Literal["low", "medium", "high"] = "medium"


class CallAnalysis(BaseModel):
    call_id: str
    status: CallStatus
    from_: str | None = Field(default=None, alias="from")
    to: str | None = None
    final_sip_code: int | None = None
    final_reason: str | None = None
    duration_seconds: float | None = None
    codec: list[str] = Field(default_factory=list)
    media: MediaStats = Field(default_factory=MediaStats)
    audio_streams: list[AudioStream] = Field(default_factory=list)
    audio_mix: AudioMix | None = None
    rtp_legs: list[RtpLeg] = Field(default_factory=list)
    sip_timeline: list[SipTimelineEvent] = Field(default_factory=list)
    diagnosis: Diagnosis
    ended_by: str | None = None
    technical: dict[str, Any] = Field(default_factory=dict)

    model_config = {"populate_by_name": True}


class Summary(BaseModel):
    total_calls: int
    failed_calls: int
    successful_calls: int


class AnalyzeResponse(BaseModel):
    filename: str
    summary: Summary
    calls: list[CallAnalysis]
    warnings: list[str] = Field(default_factory=list)
    technical: dict[str, Any] = Field(default_factory=dict)


class HealthResponse(BaseModel):
    status: Literal["ok", "degraded"]
    tshark_available: bool
    tshark_version: str | None = None
    max_upload_mb: int
