import { Download, Headphones, Pause, Play, Route, Square, Volume2 } from "lucide-react";
import { useEffect, useMemo, useRef, useState } from "react";
import type { AudioMix, AudioStream, RtpLeg } from "../types";

type PlayableAudio = AudioStream | AudioMix;

const STREAM_COLORS = ["#7fc34a", "#5d83bd", "#b08a3a", "#374151", "#d34d4d", "#7c3aed", "#0891b2", "#ea580c"];

function audioUrl(stream: PlayableAudio) {
  return stream.wav_base64 ? `data:audio/wav;base64,${stream.wav_base64}` : "";
}

function downloadWav(stream: PlayableAudio) {
  const url = audioUrl(stream);
  if (!url) return;
  const link = document.createElement("a");
  link.href = url;
  link.download = stream.wav_filename ?? `${stream.stream_id}.wav`;
  link.click();
}

function endpoint(stream: AudioStream) {
  return `${stream.source ?? "-"}:${stream.source_port ?? "-"} -> ${stream.destination ?? "-"}:${stream.destination_port ?? "-"}`;
}

function legEndpoint(leg: RtpLeg, side: "source" | "destination") {
  const ip = side === "source" ? leg.source : leg.destination;
  const port = side === "source" ? leg.source_port : leg.destination_port;
  return `${ip ?? "-"}:${port ?? "-"}`;
}

function legStatusLabel(status: RtpLeg["status"]) {
  if (status === "received") return "Com audio";
  if (status === "missing") return "Ausente";
  if (status === "no_audio") return "Sem voz";
  return "Indeterminada";
}

function percent(value: number, total: number) {
  if (!total) return "0%";
  return `${Math.round((value / total) * 100)}%`;
}

function formatTime(value: number) {
  if (!Number.isFinite(value)) return "0.0s";
  return `${value.toFixed(value >= 100 ? 0 : 1)}s`;
}

function streamDirection(stream: AudioStream, streams: AudioStream[]) {
  const firstSource = streams[0]?.source;
  return stream.source === firstSource ? "R" : "L";
}

function streamPayload(stream: AudioStream) {
  if (stream.codec) {
    const extras = stream.payload_types.filter((payload) => payload !== stream.payload_type);
    return extras.length ? `${stream.codec}, PT ${extras.join(", ")}` : stream.codec;
  }
  return `PT ${stream.payload_types.length ? stream.payload_types.join(", ") : stream.payload_type ?? "-"}`;
}

export function RtpPlayer({ streams, legs, mix }: { streams: AudioStream[]; legs: RtpLeg[]; mix: AudioMix | null }) {
  const audioRef = useRef<HTMLAudioElement | null>(null);
  const graphRef = useRef<HTMLDivElement | null>(null);
  const [currentTime, setCurrentTime] = useState(0);
  const [playing, setPlaying] = useState(false);
  const [selectedId, setSelectedId] = useState(streams.find((stream) => stream.extractable)?.stream_id ?? streams[0]?.stream_id ?? null);

  useEffect(() => {
    if (!streams.some((stream) => stream.stream_id === selectedId)) {
      setSelectedId(streams.find((stream) => stream.extractable)?.stream_id ?? streams[0]?.stream_id ?? null);
    }
  }, [selectedId, streams]);

  const selected = useMemo(
    () => streams.find((stream) => stream.stream_id === selectedId) ?? streams.find((stream) => stream.extractable) ?? streams[0] ?? null,
    [selectedId, streams],
  );

  const receivedLegs = legs.filter((leg) => leg.status === "received").length;
  const issueLegs = legs.filter((leg) => leg.status === "missing" || leg.status === "no_audio").length;
  const voicePackets = streams.reduce((total, stream) => total + stream.voice_packet_count, 0);
  const totalPackets = streams.reduce((total, stream) => total + stream.packet_count, 0);
  const firstStart = Math.min(...streams.map((stream) => stream.start_time ?? 0), 0);
  const lastEnd = Math.max(...streams.map((stream) => stream.end_time ?? 0), mix?.duration_seconds ?? 0);
  const duration = Math.max(1, mix?.duration_seconds ?? lastEnd - firstStart);
  const cursorPercent = Math.min(100, Math.max(0, (currentTime / duration) * 100));
  const tickCount = 8;

  function seekToClientX(clientX: number) {
    if (!mix?.wav_base64 || !audioRef.current) return;
    const rect = graphRef.current?.getBoundingClientRect();
    if (!rect) return;
    const ratio = Math.min(1, Math.max(0, (clientX - rect.left) / rect.width));
    audioRef.current.currentTime = ratio * duration;
    setCurrentTime(audioRef.current.currentTime);
  }

  function togglePlay() {
    if (!audioRef.current) return;
    if (audioRef.current.paused) {
      void audioRef.current.play();
    } else {
      audioRef.current.pause();
    }
  }

  function stopPlayback() {
    if (!audioRef.current) return;
    audioRef.current.pause();
    audioRef.current.currentTime = 0;
    setCurrentTime(0);
  }

  if (!streams.length && !legs.length) {
    return (
      <section className="panel">
        <div className="panelTitleWithIcon">
          <Headphones size={20} />
          <h2>RTP Player</h2>
        </div>
        <p className="muted">Nenhum stream RTP com payload de audio foi encontrado.</p>
      </section>
    );
  }

  return (
    <section className="panel rtpPlayer">
      <div className="panelHeader">
        <div className="panelTitleWithIcon">
          <Headphones size={20} />
          <h2>RTP Player</h2>
        </div>
        <span>{streams.length} stream(s), {legs.length} perna(s)</span>
      </div>

      <div className="rtpOverview">
        <article>
          <span>Pernas com voz</span>
          <strong>{receivedLegs}/{legs.length || 0}</strong>
        </article>
        <article className={issueLegs ? "attention" : ""}>
          <span>Problemas RTP</span>
          <strong>{issueLegs}</strong>
        </article>
        <article>
          <span>Pacotes de voz</span>
          <strong>{voicePackets}</strong>
        </article>
        <article>
          <span>Voz no RTP</span>
          <strong>{percent(voicePackets, totalPackets)}</strong>
        </article>
      </div>

      <div className="wiresharkPlayer">
        <div className="rtpGraph" ref={graphRef} onClick={(event) => seekToClientX(event.clientX)}>
          <div className="rtpTicks">
            {Array.from({ length: tickCount + 1 }).map((_, index) => (
              <span key={index} style={{ left: `${(index / tickCount) * 100}%` }}>
                {formatTime((duration / tickCount) * index)}
              </span>
            ))}
          </div>
          <div className="rtpCursor" style={{ left: `${cursorPercent}%` }} />
          <div className="rtpZeroLine" />
          <div className="rtpGraphLegend">
            <span><i className="legendJitter" /> Jitter Drops</span>
            <span><i className="legendWrong" /> Wrong Timestamps</span>
            <span><i className="legendSilence" /> Inserted Silence</span>
            <span><i className="legendOut" /> Out of Sequence</span>
          </div>
          {streams.map((stream, streamIndex) => {
            const color = STREAM_COLORS[streamIndex % STREAM_COLORS.length];
            const laneTop = 12 + streamIndex * (76 / Math.max(streams.length, 1));
            const laneHeight = Math.max(11, 54 / Math.max(streams.length, 1));
            const start = Math.max(0, (stream.start_time ?? firstStart) - firstStart);
            const end = Math.max(start + 0.1, (stream.end_time ?? firstStart + start + (stream.duration_seconds ?? 1)) - firstStart);
            const left = (start / duration) * 100;
            const width = Math.max(0.4, ((end - start) / duration) * 100);
            const peaks = stream.waveform.length ? stream.waveform : Array.from({ length: 80 }, () => 0.02);
            return (
              <div
                className={`rtpGraphStream ${stream.stream_id === selected?.stream_id ? "selected" : ""}`}
                key={stream.stream_id}
                style={{ left: `${left}%`, width: `${width}%`, top: `${laneTop}%`, height: `${laneHeight}%` }}
                onClick={(event) => {
                  event.stopPropagation();
                  setSelectedId(stream.stream_id);
                  seekToClientX(event.clientX);
                }}
                title={endpoint(stream)}
              >
                {peaks.map((peak, index) => (
                  <span
                    key={`${stream.stream_id}-${index}`}
                    style={{
                      background: color,
                      height: `${Math.max(2, peak * 100)}%`,
                    }}
                  />
                ))}
              </div>
            );
          })}
        </div>

        <div className="rtpStreamTable">
          <table>
            <thead>
              <tr>
                <th>Play</th>
                <th>Source Address</th>
                <th>Source Port</th>
                <th>Destination Address</th>
                <th>Destination Port</th>
                <th>SSRC</th>
                <th>Packets</th>
                <th>Seq Loss</th>
                <th>Dup/OoO</th>
                <th>Time Span (s)</th>
                <th>SR (Hz)</th>
                <th>Payloads</th>
              </tr>
            </thead>
            <tbody>
              {streams.map((stream, index) => (
                <tr
                  className={stream.stream_id === selected?.stream_id ? "selected" : ""}
                  key={stream.stream_id}
                  onClick={() => setSelectedId(stream.stream_id)}
                  style={{ color: STREAM_COLORS[index % STREAM_COLORS.length] }}
                >
                  <td>{streamDirection(stream, streams)}</td>
                  <td>{stream.source ?? "-"}</td>
                  <td>{stream.source_port ?? "-"}</td>
                  <td>{stream.destination ?? "-"}</td>
                  <td>{stream.destination_port ?? "-"}</td>
                  <td className="mono">{stream.ssrc ?? "-"}</td>
                  <td>{stream.packet_count}</td>
                  <td>{stream.lost_packet_count ? `${stream.lost_packet_count} / ${stream.sequence_gap_count}` : "-"}</td>
                  <td>{stream.duplicate_packet_count || stream.out_of_order_packet_count ? `${stream.duplicate_packet_count}/${stream.out_of_order_packet_count}` : "-"}</td>
                  <td>{(stream.start_time ?? 0).toFixed(2)} - {(stream.end_time ?? 0).toFixed(2)}</td>
                  <td>{stream.sample_rate_hz}</td>
                  <td>{streamPayload(stream)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>

        <div className="rtpStatusLine">
          {streams.length} streams, {streams.filter((stream) => !stream.extractable).length} not playable, start: {formatTime(firstStart)}.
          Clique no grafico para posicionar a reproducao.
        </div>

        <div className="rtpToolbar">
          <button type="button" disabled={!mix?.wav_base64} onClick={togglePlay}>
            {playing ? <Pause size={18} /> : <Play size={18} />}
          </button>
          <button type="button" disabled={!mix?.wav_base64} onClick={stopPlayback}>
            <Square size={18} />
          </button>
          <div className="rtpTimeReadout">
            {formatTime(currentTime)} / {formatTime(duration)}
          </div>
          {mix?.wav_base64 ? (
            <audio
              controls
              ref={audioRef}
              src={audioUrl(mix)}
              onEnded={() => setPlaying(false)}
              onPause={() => setPlaying(false)}
              onPlay={() => setPlaying(true)}
              onTimeUpdate={(event) => setCurrentTime(event.currentTarget.currentTime)}
            />
          ) : (
            <span className="muted">Audio completo indisponivel para reproducao.</span>
          )}
          {mix?.wav_base64 && (
            <button type="button" onClick={() => downloadWav(mix)}>
              <Download size={18} />
              WAV completo
            </button>
          )}
        </div>
      </div>

      <div className="rtpLegSummary">
        {legs.map((leg) => (
          <article className={`rtpLegCard ${leg.status}`} key={leg.leg_id}>
            <div>
              <Route size={17} />
              <strong>{legStatusLabel(leg.status)}</strong>
              <span className={`rtpBadge ${leg.status}`}>{leg.status}</span>
            </div>
            <p>{legEndpoint(leg, "source")} {"->"} {legEndpoint(leg, "destination")}</p>
            <span>
              {leg.packet_count ? `${leg.packet_count} pacotes` : "0 pacotes"} | {leg.voice_packet_count} voz |{" "}
              {leg.codecs.length ? leg.codecs.join(", ") : leg.payload_types.length ? `PT ${leg.payload_types.join(", ")}` : "sem payload"}
            </span>
            {leg.note && <small>{leg.note}</small>}
          </article>
        ))}
      </div>

      {selected && (
        <div className="rtpSelected">
          <Volume2 size={18} />
          <strong>{endpoint(selected)}</strong>
          <span>{selected.voice_packet_count} voz | {percent(selected.voice_packet_count, selected.packet_count)} do stream</span>
          <button type="button" disabled={!selected.extractable} onClick={() => downloadWav(selected)}>
            <Download size={18} />
            WAV da perna
          </button>
        </div>
      )}
    </section>
  );
}
