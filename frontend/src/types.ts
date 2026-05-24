export type CallStatus = "success" | "failed" | "warning";
export type Severity = "info" | "warning" | "critical";

export interface MediaStats {
  rtp_detected: boolean;
  directions: number;
  packet_loss_percent: number | null;
  max_jitter_ms: number | null;
}

export interface AudioStream {
  stream_id: string;
  source: string | null;
  source_port: number | null;
  destination: string | null;
  destination_port: number | null;
  ssrc: string | null;
  payload_type: number | null;
  payload_types: number[];
  codec: string | null;
  sample_rate_hz: number;
  packet_count: number;
  voice_packet_count: number;
  expected_packet_count: number | null;
  sequence_gap_count: number;
  lost_packet_count: number;
  duplicate_packet_count: number;
  out_of_order_packet_count: number;
  max_sequence_gap: number;
  rtp_sequence_gaps: Record<string, unknown>[];
  duration_seconds: number | null;
  start_time: number | null;
  end_time: number | null;
  extractable: boolean;
  unsupported_reason: string | null;
  wav_base64: string | null;
  wav_filename: string | null;
  waveform: number[];
}

export interface AudioMix {
  stream_id: string;
  codec: string;
  sample_rate_hz: number;
  duration_seconds: number | null;
  wav_base64: string | null;
  wav_filename: string | null;
  waveform: number[];
}

export interface RtpLeg {
  leg_id: string;
  status: "received" | "missing" | "no_audio" | "unknown";
  source: string | null;
  source_port: number | null;
  destination: string | null;
  destination_port: number | null;
  packet_count: number;
  voice_packet_count: number;
  payload_types: number[];
  codecs: string[];
  ssrc: string[];
  start_time: number | null;
  end_time: number | null;
  duration_seconds: number | null;
  audio_stream_id: string | null;
  note: string | null;
}

export interface SipTimelineEvent {
  time: number;
  source: string | null;
  destination: string | null;
  method: string | null;
  status_code: number | null;
  reason: string | null;
}

export interface Diagnosis {
  probable_cause: string;
  resolution: string;
  severity: Severity;
  category: string | null;
  evidence: string[];
  suggested_checks: string[];
  confidence: "low" | "medium" | "high";
}

export interface CallAnalysis {
  call_id: string;
  status: CallStatus;
  from: string | null;
  to: string | null;
  final_sip_code: number | null;
  final_reason: string | null;
  duration_seconds: number | null;
  codec: string[];
  media: MediaStats;
  audio_streams: AudioStream[];
  audio_mix: AudioMix | null;
  rtp_legs: RtpLeg[];
  sip_timeline: SipTimelineEvent[];
  diagnosis: Diagnosis;
  ended_by?: string | null;
  technical: Record<string, unknown>;
}

export interface AnalyzeResponse {
  filename: string;
  summary: {
    total_calls: number;
    failed_calls: number;
    successful_calls: number;
  };
  calls: CallAnalysis[];
  warnings: string[];
  technical: Record<string, unknown>;
}

export interface HealthResponse {
  status: "ok" | "degraded";
  tshark_available: boolean;
  tshark_version: string | null;
  max_upload_mb: number;
}
