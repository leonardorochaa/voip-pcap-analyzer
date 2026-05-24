import { useEffect, useMemo, useState } from "react";
import { Clipboard, Download, FileCode2, FileJson, ServerCrash } from "lucide-react";
import { analyzePcap, getHealth } from "./api";
import { CallTable } from "./components/CallTable";
import { Dashboard } from "./components/Dashboard";
import { DiagnosisPanel } from "./components/DiagnosisPanel";
import { RtpPlayer } from "./components/RtpPlayer";
import { SipTimeline } from "./components/SipTimeline";
import { TechnicalJson } from "./components/TechnicalJson";
import { UploadBox } from "./components/UploadBox";
import type { AnalyzeResponse, CallAnalysis, HealthResponse } from "./types";

function downloadFile(filename: string, content: string, mimeType: string) {
  const blob = new Blob([content], { type: mimeType });
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = filename;
  link.click();
  URL.revokeObjectURL(url);
}

function finalSip(call: CallAnalysis) {
  return `${call.final_sip_code ?? "-"} ${call.final_reason ?? ""}`.trim();
}

function technicalItems(call: CallAnalysis, key: string): Record<string, unknown>[] {
  const value = call.technical[key];
  if (!Array.isArray(value)) return [];
  return value.filter((item): item is Record<string, unknown> => item !== null && typeof item === "object" && !Array.isArray(item));
}

function asText(value: unknown, fallback = "-") {
  if (value === null || value === undefined || value === "") return fallback;
  if (Array.isArray(value)) return value.join(", ");
  return String(value);
}

function callTitle(call: CallAnalysis, index: number) {
  return `Chamada ${index + 1} - ${call.from ?? "-"} -> ${call.to ?? "-"}`;
}

function escapeHtml(value: string) {
  return value.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
}

function summaryText(result: AnalyzeResponse) {
  return result.calls
    .map((call, index) => {
      const missing = call.rtp_legs.filter((leg) => leg.status === "missing").length;
      const noAudio = call.rtp_legs.filter((leg) => leg.status === "no_audio").length;
      const retransmissions = technicalItems(call, "sip_retransmissions").reduce(
        (total, item) => total + Number(item.retransmission_count ?? 0),
        0,
      );
      const lostPackets = technicalItems(call, "rtp_sequence_analysis").reduce(
        (total, item) => total + Number(item.lost_packet_count ?? 0),
        0,
      );
      return [
        callTitle(call, index),
        `Status: ${call.status}`,
        `SIP final: ${finalSip(call)}`,
        `RTP: ${call.media.rtp_detected ? `${call.media.directions} direcao(oes)` : "nao detectado"}`,
        `Problemas RTP: ${missing} ausente(s), ${noAudio} sem voz`,
        `Retransmissoes SIP: ${retransmissions}`,
        `Pacotes RTP ausentes estimados: ${lostPackets}`,
        `Diagnostico: ${call.diagnosis.probable_cause}`,
        `Evidencias: ${call.diagnosis.evidence.length ? call.diagnosis.evidence.join("; ") : "-"}`,
        `Resolucao: ${call.diagnosis.resolution}`,
      ].join("\n");
    })
    .join("\n\n");
}

function markdownReport(result: AnalyzeResponse) {
  const lines = [
    `# Relatorio VoIP - ${result.filename}`,
    "",
    "## Resumo",
    `- Total de chamadas: ${result.summary.total_calls}`,
    `- Chamadas com sucesso: ${result.summary.successful_calls}`,
    `- Chamadas com falha: ${result.summary.failed_calls}`,
    `- Avisos: ${result.warnings.length}`,
    "",
  ];

  result.calls.forEach((call, index) => {
    const missing = call.rtp_legs.filter((leg) => leg.status === "missing").length;
    const noAudio = call.rtp_legs.filter((leg) => leg.status === "no_audio").length;
    const sdpRtp = technicalItems(call, "sdp_rtp_comparison");
    const retransmissions = technicalItems(call, "sip_retransmissions");
    const sequenceAnalysis = technicalItems(call, "rtp_sequence_analysis");
    lines.push(
      `## ${callTitle(call, index)}`,
      `- Call-ID: ${call.call_id}`,
      `- Status: ${call.status}`,
      `- Codigo SIP final: ${finalSip(call)}`,
      `- Duracao estimada: ${call.duration_seconds ?? "-"}s`,
      `- Codec: ${call.codec.length ? call.codec.join(", ") : "-"}`,
      `- RTP detectado: ${call.media.rtp_detected ? "sim" : "nao"}`,
      `- Direcoes RTP: ${call.media.directions}`,
      `- Perda RTP: ${call.media.packet_loss_percent ?? "-"}%`,
      `- Jitter: ${call.media.max_jitter_ms ?? "-"} ms`,
      `- Pernas RTP ausentes: ${missing}`,
      `- Pernas RTP sem voz: ${noAudio}`,
      "",
      "### Diagnostico",
      call.diagnosis.probable_cause,
      "",
      "### Evidencias tecnicas",
      ...(call.diagnosis.evidence.length ? call.diagnosis.evidence.map((item) => `- ${item}`) : ["- Sem evidencias estruturadas adicionais."]),
      "",
      "### Resolucao sugerida",
      call.diagnosis.resolution,
      "",
      "### Comparacao SDP x RTP",
      ...(sdpRtp.length ? sdpRtp.map((item) => `- [${asText(item.severity)}] ${asText(item.message)}`) : ["- Sem comparacao SDP x RTP disponivel."]),
      "",
      "### Retransmissoes SIP",
      ...(
        retransmissions.length
          ? retransmissions.map(
              (item) =>
                `- ${asText(item.event, "SIP")} ${asText(item.source)} -> ${asText(item.destination)}: ${asText(item.retransmission_count, "0")} retransmissao(oes), intervalos ${asText(item.intervals_ms, "[]")} ms`,
            )
          : ["- Nenhuma retransmissao SIP detectada."]
      ),
      "",
      "### Gaps de sequencia RTP",
      ...(
        sequenceAnalysis.length
          ? sequenceAnalysis.map(
              (item) =>
                `- ${asText(item.stream_id)}: ${asText(item.lost_packet_count, "0")} pacote(s) estimado(s) ausente(s), ${asText(item.sequence_gap_count, "0")} gap(s), ${asText(item.duplicate_packet_count, "0")} duplicado(s), ${asText(item.out_of_order_packet_count, "0")} fora de ordem`,
            )
          : ["- Nenhum gap de sequencia RTP detectado."]
      ),
      "",
      "### Pernas RTP",
      "| Status | Origem | Destino | Pacotes | Voz | Codec/Payload |",
      "|---|---|---|---:|---:|---|",
    );

    call.rtp_legs.forEach((leg) => {
      lines.push(
        `| ${leg.status} | ${leg.source ?? "-"}:${leg.source_port ?? "-"} | ${leg.destination ?? "-"}:${leg.destination_port ?? "-"} | ${leg.packet_count} | ${leg.voice_packet_count} | ${leg.codecs.join(", ") || leg.payload_types.join(", ") || "-"} |`,
      );
    });

    lines.push("", "### Streams RTP", "| Origem | Destino | SSRC | Pacotes | Voz | Codec/Payload | Tempo |", "|---|---|---|---:|---:|---|---|");
    call.audio_streams.forEach((stream) => {
      lines.push(
        `| ${stream.source ?? "-"}:${stream.source_port ?? "-"} | ${stream.destination ?? "-"}:${stream.destination_port ?? "-"} | ${stream.ssrc ?? "-"} | ${stream.packet_count} | ${stream.voice_packet_count} | ${stream.codec ?? (stream.payload_types.join(", ") || "-")} | ${stream.start_time ?? "-"} - ${stream.end_time ?? "-"}s |`,
      );
    });

    lines.push("", "### Timeline SIP");
    call.sip_timeline.forEach((event) => {
      const label = event.status_code ? `${event.status_code} ${event.reason ?? ""}`.trim() : event.method ?? "SIP";
      lines.push(`- ${event.time.toFixed(3)}s ${event.source ?? "-"} -> ${event.destination ?? "-"}: ${label}`);
    });
    lines.push("");
  });

  return lines.join("\n");
}

function htmlReport(result: AnalyzeResponse) {
  const sections = result.calls
    .map((call, index) => {
      const rtpRows = call.rtp_legs
        .map(
          (leg) => `<tr>
            <td><span class="badge ${leg.status}">${escapeHtml(leg.status)}</span></td>
            <td>${escapeHtml(`${leg.source ?? "-"}:${leg.source_port ?? "-"}`)}</td>
            <td>${escapeHtml(`${leg.destination ?? "-"}:${leg.destination_port ?? "-"}`)}</td>
            <td>${leg.packet_count}</td>
            <td>${leg.voice_packet_count}</td>
            <td>${escapeHtml(leg.codecs.join(", ") || leg.payload_types.join(", ") || "-")}</td>
          </tr>`,
        )
        .join("");
      const sipRows = call.sip_timeline
        .map((event) => {
          const label = event.status_code ? `${event.status_code} ${event.reason ?? ""}`.trim() : event.method ?? "SIP";
          return `<tr><td>${event.time.toFixed(3)}s</td><td>${escapeHtml(event.source ?? "-")}</td><td>${escapeHtml(event.destination ?? "-")}</td><td>${escapeHtml(label)}</td></tr>`;
        })
        .join("");
      const evidence = call.diagnosis.evidence.length
        ? `<ul>${call.diagnosis.evidence.map((item) => `<li>${escapeHtml(item)}</li>`).join("")}</ul>`
        : "<p>Sem evidencias estruturadas adicionais.</p>";
      const sdpRtpRows = technicalItems(call, "sdp_rtp_comparison")
        .map((item) => `<tr><td>${escapeHtml(asText(item.severity))}</td><td>${escapeHtml(asText(item.type))}</td><td>${escapeHtml(asText(item.message))}</td></tr>`)
        .join("");
      const retransmissionRows = technicalItems(call, "sip_retransmissions")
        .map(
          (item) =>
            `<tr><td>${escapeHtml(asText(item.event, "SIP"))}</td><td>${escapeHtml(asText(item.source))}</td><td>${escapeHtml(asText(item.destination))}</td><td>${escapeHtml(asText(item.retransmission_count, "0"))}</td><td>${escapeHtml(asText(item.intervals_ms, "[]"))}</td></tr>`,
        )
        .join("");
      const sequenceRows = technicalItems(call, "rtp_sequence_analysis")
        .map(
          (item) =>
            `<tr><td>${escapeHtml(asText(item.stream_id))}</td><td>${escapeHtml(asText(item.lost_packet_count, "0"))}</td><td>${escapeHtml(asText(item.sequence_gap_count, "0"))}</td><td>${escapeHtml(asText(item.duplicate_packet_count, "0"))}</td><td>${escapeHtml(asText(item.out_of_order_packet_count, "0"))}</td></tr>`,
        )
        .join("");
      return `<section>
        <h2>${escapeHtml(callTitle(call, index))}</h2>
        <div class="cards">
          <div><span>Status</span><strong>${escapeHtml(call.status)}</strong></div>
          <div><span>SIP final</span><strong>${escapeHtml(finalSip(call))}</strong></div>
          <div><span>Duracao</span><strong>${call.duration_seconds ?? "-"}s</strong></div>
          <div><span>Codec</span><strong>${escapeHtml(call.codec.join(", ") || "-")}</strong></div>
        </div>
        <h3>Diagnostico</h3><p>${escapeHtml(call.diagnosis.probable_cause)}</p>
        <h3>Evidencias tecnicas</h3>${evidence}
        <h3>Resolucao sugerida</h3><p>${escapeHtml(call.diagnosis.resolution)}</p>
        <h3>Comparacao SDP x RTP</h3>
        <table><thead><tr><th>Severidade</th><th>Tipo</th><th>Evidencia</th></tr></thead><tbody>${sdpRtpRows || `<tr><td colspan="3">Sem comparacao SDP x RTP disponivel.</td></tr>`}</tbody></table>
        <h3>Retransmissoes SIP</h3>
        <table><thead><tr><th>Evento</th><th>Origem</th><th>Destino</th><th>Qtd.</th><th>Intervalos ms</th></tr></thead><tbody>${retransmissionRows || `<tr><td colspan="5">Nenhuma retransmissao SIP detectada.</td></tr>`}</tbody></table>
        <h3>Gaps de sequencia RTP</h3>
        <table><thead><tr><th>Stream</th><th>Perdidos</th><th>Gaps</th><th>Duplicados</th><th>Fora de ordem</th></tr></thead><tbody>${sequenceRows || `<tr><td colspan="5">Nenhum gap de sequencia RTP detectado.</td></tr>`}</tbody></table>
        <h3>Pernas RTP</h3>
        <table><thead><tr><th>Status</th><th>Origem</th><th>Destino</th><th>Pacotes</th><th>Voz</th><th>Codec/Payload</th></tr></thead><tbody>${rtpRows}</tbody></table>
        <h3>Timeline SIP</h3>
        <table><thead><tr><th>Tempo</th><th>Origem</th><th>Destino</th><th>Evento</th></tr></thead><tbody>${sipRows}</tbody></table>
      </section>`;
    })
    .join("");

  return `<!doctype html><html lang="pt-BR"><head><meta charset="utf-8" />
  <title>Relatorio VoIP - ${escapeHtml(result.filename)}</title>
  <style>
    body{font-family:Arial,Helvetica,sans-serif;background:#eef2f6;color:#17202a;margin:0;padding:28px}
    main{max-width:1180px;margin:0 auto;background:#fff;border:1px solid #d9e1ec;border-radius:8px;padding:24px}
    h1,h2,h3{margin:0 0 12px} section{border-top:1px solid #dbe4ef;padding-top:20px;margin-top:20px}
    .cards{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:10px;margin:14px 0}
    .cards div{border:1px solid #dbe4ef;border-radius:8px;padding:12px;background:#f8fafc}
    .cards span{display:block;color:#64748b;font-size:12px;font-weight:700;text-transform:uppercase}.cards strong{font-size:18px}
    table{border-collapse:collapse;width:100%;margin:10px 0 18px}th,td{border-bottom:1px solid #e2e8f0;text-align:left;padding:8px;font-size:13px}th{color:#526173;text-transform:uppercase;font-size:12px}
    .badge{border-radius:999px;padding:4px 8px;font-weight:700;font-size:12px}.received{background:#dcfce7;color:#166534}.missing{background:#fee2e2;color:#991b1b}.no_audio{background:#ffedd5;color:#9a3412}.unknown{background:#e2e8f0;color:#475569}
  </style></head><body><main><h1>Relatorio VoIP - ${escapeHtml(result.filename)}</h1><p>Total: ${result.summary.total_calls} | Sucesso: ${result.summary.successful_calls} | Falha: ${result.summary.failed_calls}</p>${sections}</main></body></html>`;
}

function redactedTechnicalPayload(call: CallAnalysis, result: AnalyzeResponse) {
  return {
    selected_call: {
      ...call,
      audio_streams: call.audio_streams.map((stream) => ({
        ...stream,
        wav_base64: stream.wav_base64 ? `[base64 wav ${stream.wav_base64.length} chars]` : null,
      })),
      audio_mix: call.audio_mix
        ? {
            ...call.audio_mix,
            wav_base64: call.audio_mix.wav_base64 ? `[base64 wav ${call.audio_mix.wav_base64.length} chars]` : null,
          }
        : null,
    },
    capture: result.technical,
    warnings: result.warnings,
  };
}

function Header({ health }: { health: HealthResponse | null }) {
  return (
    <header className="appHeader">
      <div>
        <h1>VoIP PCAP Analyzer</h1>
        <p>Analise visual de chamadas SIP/RTP a partir de PCAP ou PCAPNG.</p>
      </div>
      <div className={`healthBadge ${health?.tshark_available ? "ok" : "bad"}`}>
        <span />
        {health ? (health.tshark_available ? "tshark disponivel" : "tshark indisponivel") : "verificando backend"}
      </div>
    </header>
  );
}

export default function App() {
  const [health, setHealth] = useState<HealthResponse | null>(null);
  const [result, setResult] = useState<AnalyzeResponse | null>(null);
  const [selectedCallId, setSelectedCallId] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [copyStatus, setCopyStatus] = useState<string | null>(null);

  useEffect(() => {
    getHealth()
      .then(setHealth)
      .catch((err: Error) => setError(`Backend indisponivel: ${err.message}`));
  }, []);

  const selectedCall: CallAnalysis | null = useMemo(() => {
    if (!result) return null;
    return result.calls.find((call) => call.call_id === selectedCallId) ?? result.calls[0] ?? null;
  }, [result, selectedCallId]);

  async function handleUpload(file: File) {
    setLoading(true);
    setError(null);
    setCopyStatus(null);
    try {
      const analysis = await analyzePcap(file);
      setResult(analysis);
      setSelectedCallId(analysis.calls[0]?.call_id ?? null);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Falha ao analisar arquivo.");
    } finally {
      setLoading(false);
    }
  }

  async function copySummary(resultToCopy: AnalyzeResponse) {
    await navigator.clipboard.writeText(summaryText(resultToCopy));
    setCopyStatus("Resumo copiado");
    window.setTimeout(() => setCopyStatus(null), 2500);
  }

  return (
    <main className="appShell">
      <Header health={health} />

      <UploadBox loading={loading} onUpload={handleUpload} />

      {error && (
        <div className="errorBanner">
          <ServerCrash size={18} />
          {error}
        </div>
      )}

      {result && (
        <div className="resultStack">
          <div className="resultHeader">
            <div>
              <span className="eyebrow">Arquivo analisado</span>
              <h2>{result.filename}</h2>
              {copyStatus && <span className="copyStatus">{copyStatus}</span>}
            </div>
            <div className="actions">
              <button type="button" onClick={() => copySummary(result)}>
                <Clipboard size={18} />
                Copiar resumo
              </button>
              <button type="button" onClick={() => downloadFile(`${result.filename}.report.md`, markdownReport(result), "text/markdown")}>
                <Download size={18} />
                Markdown
              </button>
              <button type="button" onClick={() => downloadFile(`${result.filename}.report.html`, htmlReport(result), "text/html")}>
                <FileCode2 size={18} />
                HTML
              </button>
              <button type="button" onClick={() => downloadFile(`${result.filename}.json`, JSON.stringify(result, null, 2), "application/json")}>
                <FileJson size={18} />
                JSON
              </button>
            </div>
          </div>

          {result.warnings.length > 0 && (
            <div className="warningList">
              {result.warnings.map((warning) => (
                <span key={warning}>{warning}</span>
              ))}
            </div>
          )}

          <CallTable calls={result.calls} selectedCallId={selectedCall?.call_id ?? null} onSelect={setSelectedCallId} />

          {selectedCall && (
            <>
              <Dashboard call={selectedCall} />
              <RtpPlayer streams={selectedCall.audio_streams ?? []} legs={selectedCall.rtp_legs ?? []} mix={selectedCall.audio_mix ?? null} />
              <SipTimeline events={selectedCall.sip_timeline} rtpLegs={selectedCall.rtp_legs ?? []} />
              <DiagnosisPanel call={selectedCall} />
              <TechnicalJson payload={redactedTechnicalPayload(selectedCall, result)} />
            </>
          )}
        </div>
      )}
    </main>
  );
}
