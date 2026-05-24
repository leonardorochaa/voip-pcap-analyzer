import { Activity, AlertTriangle, CheckCircle2, Clock, Radio, Route, Signal, Timer } from "lucide-react";
import type { CallAnalysis } from "../types";

function formatValue(value: string | number | null | undefined, fallback = "-") {
  return value === null || value === undefined || value === "" ? fallback : value;
}

function formatPercent(value: number | null) {
  return value === null ? "-" : `${value.toFixed(2)}%`;
}

function statusLabel(call: CallAnalysis) {
  if (call.status === "success") return "Sucesso";
  if (call.status === "failed") return "Falha";
  return "Atencao";
}

export function Dashboard({ call }: { call: CallAnalysis }) {
  const cards = [
    {
      label: "Status da chamada",
      value: statusLabel(call),
      icon: call.status === "success" ? CheckCircle2 : AlertTriangle,
      tone: call.status,
    },
    {
      label: "Codigo SIP final",
      value: call.final_sip_code ? `${call.final_sip_code} ${call.final_reason ?? ""}` : "-",
      icon: Route,
      tone: call.status,
    },
    {
      label: "Duracao estimada",
      value: call.duration_seconds === null ? "-" : `${call.duration_seconds.toFixed(1)}s`,
      icon: Clock,
      tone: "neutral",
    },
    {
      label: "Codec",
      value: call.codec.length ? call.codec.join(", ") : "-",
      icon: Radio,
      tone: "neutral",
    },
    {
      label: "RTP detectado",
      value: call.media.rtp_detected ? `${call.media.directions} direcao(oes)` : "Nao",
      icon: Activity,
      tone: call.media.rtp_detected ? "success" : "warning",
    },
    {
      label: "Perda RTP",
      value: formatPercent(call.media.packet_loss_percent),
      icon: Signal,
      tone: call.media.packet_loss_percent !== null && call.media.packet_loss_percent >= 3 ? "warning" : "neutral",
    },
    {
      label: "Jitter",
      value: call.media.max_jitter_ms === null ? "-" : `${call.media.max_jitter_ms.toFixed(2)} ms`,
      icon: Timer,
      tone: call.media.max_jitter_ms !== null && call.media.max_jitter_ms >= 30 ? "warning" : "neutral",
    },
    {
      label: "Causa provavel",
      value: formatValue(call.diagnosis.probable_cause),
      icon: AlertTriangle,
      tone: call.diagnosis.severity,
    },
  ];

  return (
    <section className="dashboardGrid">
      {cards.map((card) => {
        const Icon = card.icon;
        return (
          <article className={`metricCard tone-${card.tone}`} key={card.label}>
            <div className="metricTop">
              <span>{card.label}</span>
              <Icon size={18} />
            </div>
            <strong>{card.value}</strong>
          </article>
        );
      })}
    </section>
  );
}
