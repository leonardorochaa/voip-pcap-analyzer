import { Maximize2, Minimize2 } from "lucide-react";
import { useMemo, useState } from "react";
import type { RtpLeg, SipTimelineEvent } from "../types";

function eventLabel(event: SipTimelineEvent) {
  if (event.status_code) {
    return `${event.status_code} ${event.reason ?? ""}`.trim();
  }
  return event.method ?? "SIP";
}

function isError(event: SipTimelineEvent) {
  return event.status_code !== null && event.status_code >= 400;
}

function isExpected(event: SipTimelineEvent) {
  const label = eventLabel(event);
  return ["INVITE", "100 Trying", "180 Ringing", "183 Session Progress", "200 OK", "ACK", "BYE", "CANCEL"].some((item) =>
    label.startsWith(item),
  );
}

type LadderRow =
  | {
      type: "sip";
      time: number;
      source: string | null;
      destination: string | null;
      label: string;
      comment: string;
      error: boolean;
    }
  | {
      type: "rtp";
      time: number;
      source: string | null;
      destination: string | null;
      label: string;
      comment: string;
      error: boolean;
    };

type FlowFilter = "all" | "sip" | "rtp" | "issues";
type FlowDensity = "comfortable" | "compact";

function collectParticipants(events: SipTimelineEvent[], rtpLegs: RtpLeg[]) {
  const participants: string[] = [];
  [...events.flatMap((event) => [event.source, event.destination]), ...rtpLegs.flatMap((leg) => [leg.source, leg.destination])]
    .filter((value): value is string => Boolean(value))
    .forEach((value) => {
      if (!participants.includes(value)) participants.push(value);
    });
  return participants.length ? participants : ["origem", "destino"];
}

function rowLabel(row: LadderRow) {
  return row.type === "rtp" ? row.label : row.label;
}

export function SipTimeline({ events, rtpLegs = [] }: { events: SipTimelineEvent[]; rtpLegs?: RtpLeg[] }) {
  const [expanded, setExpanded] = useState(false);
  const [filter, setFilter] = useState<FlowFilter>("all");
  const [density, setDensity] = useState<FlowDensity>("comfortable");
  const participants = useMemo(() => collectParticipants(events, rtpLegs), [events, rtpLegs]);
  const participantCount = Math.max(participants.length, 2);
  const rows: LadderRow[] = useMemo(
    () =>
      [
        ...events.map((event) => ({
          type: "sip" as const,
          time: event.time,
          source: event.source,
          destination: event.destination,
          label: eventLabel(event),
          comment: event.status_code
            ? `SIP Status ${event.status_code} ${event.reason ?? ""}`.trim()
            : `SIP Request ${event.method ?? ""}`.trim(),
          error: isError(event),
        })),
        ...rtpLegs.map((leg) => ({
          type: "rtp" as const,
          time: leg.start_time ?? 0,
          source: leg.source,
          destination: leg.destination,
          label:
            leg.status === "missing"
              ? "RTP ausente"
              : leg.status === "no_audio"
                ? "RTP sem voz"
                : `RTP (${leg.codecs.join(", ") || (leg.payload_types.length ? `PT ${leg.payload_types.join(", ")}` : "payload")})`,
          comment:
            leg.status === "missing"
              ? leg.note ?? "RTP esperado pelo SDP, mas nao visto no PCAP"
              : leg.status === "no_audio"
                ? leg.note ?? "RTP recebido, mas sem audio de voz util"
              : `RTP, ${leg.packet_count} pacotes, voz ${leg.voice_packet_count}, duracao ${leg.duration_seconds ?? "-"}s`,
          error: leg.status === "missing" || leg.status === "no_audio",
        })),
      ].sort((a, b) => a.time - b.time),
    [events, rtpLegs],
  );
  const filteredRows = rows.filter((row) => {
    if (filter === "sip") return row.type === "sip";
    if (filter === "rtp") return row.type === "rtp";
    if (filter === "issues") return row.error;
    return true;
  });

  if (!events.length && !rtpLegs.length) {
    return (
      <section className="panel">
        <h2>Fluxo SIP/RTP</h2>
        <p className="muted">Nenhum evento SIP encontrado.</p>
      </section>
    );
  }

  return (
    <section className={`panel ladderPanel ${expanded ? "expanded" : ""} ${density}`}>
      <div className="ladderTitle">
        <div>
          <h2>Fluxo SIP/RTP</h2>
          <span>
            {filteredRows.length} de {rows.length} eventos | {participants.length} participante(s)
          </span>
        </div>
        <div className="ladderControls">
          <div className="segmented" aria-label="Filtro do fluxo">
            {[
              ["all", "Tudo"],
              ["sip", "SIP"],
              ["rtp", "RTP"],
              ["issues", "Problemas"],
            ].map(([value, label]) => (
              <button
                className={filter === value ? "active" : ""}
                key={value}
                type="button"
                onClick={() => setFilter(value as FlowFilter)}
              >
                {label}
              </button>
            ))}
          </div>
          <div className="segmented" aria-label="Densidade do fluxo">
            {[
              ["comfortable", "Detalhado"],
              ["compact", "Compacto"],
            ].map(([value, label]) => (
              <button
                className={density === value ? "active" : ""}
                key={value}
                type="button"
                onClick={() => setDensity(value as FlowDensity)}
              >
                {label}
              </button>
            ))}
          </div>
          <button type="button" className="secondaryButton" onClick={() => setExpanded((value) => !value)}>
            {expanded ? <Minimize2 size={18} /> : <Maximize2 size={18} />}
            {expanded ? "Sair" : "Tela cheia"}
          </button>
        </div>
      </div>
      <div className="ladderScroll">
        <div className="ladder" style={{ minWidth: `${Math.max(960, participantCount * 300 + 360)}px` }}>
          <div className="ladderHeader">
            <span>Time</span>
            <div className="ladderParticipants" style={{ gridTemplateColumns: `repeat(${participantCount}, 1fr)` }}>
              {participants.map((participant) => (
                <strong key={participant}>{participant}</strong>
              ))}
            </div>
            <span>Comment</span>
          </div>

          {filteredRows.map((row, index) => {
            const srcIndex = Math.max(0, participants.indexOf(row.source ?? ""));
            const dstIndex = Math.max(0, participants.indexOf(row.destination ?? ""));
            const from = Math.min(srcIndex, dstIndex);
            const to = Math.max(srcIndex, dstIndex);
            const left = participantCount === 1 ? 50 : (from / (participantCount - 1)) * 100;
            const right = participantCount === 1 ? 50 : (to / (participantCount - 1)) * 100;
            const reverse = srcIndex > dstIndex;

            return (
              <div className={`ladderRow ${row.type} ${row.error ? "error" : ""}`} key={`${row.type}-${row.time}-${index}`}>
                <span className="ladderTime">{row.time.toFixed(6)}</span>
                <div className="ladderCanvas" style={{ gridTemplateColumns: `repeat(${participantCount}, 1fr)` }}>
                  {participants.map((participant) => (
                    <span className="ladderLane" key={participant} />
                  ))}
                  <div
                    className={`ladderArrow ${reverse ? "reverse" : ""}`}
                    style={{
                      left: `${left}%`,
                      width: `${Math.max(8, right - left)}%`,
                    }}
                  >
                    <span>{rowLabel(row)}</span>
                  </div>
                </div>
                <span className="ladderComment">{row.comment}</span>
              </div>
            );
          })}
        </div>
      </div>
    </section>
  );
}
