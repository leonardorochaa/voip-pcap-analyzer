import type { CallAnalysis } from "../types";

interface CallTableProps {
  calls: CallAnalysis[];
  selectedCallId: string | null;
  onSelect: (callId: string) => void;
}

export function CallTable({ calls, selectedCallId, onSelect }: CallTableProps) {
  return (
    <section className="panel tablePanel">
      <div className="panelHeader">
        <h2>Chamadas</h2>
        <span>{calls.length} Call-ID(s)</span>
      </div>
      <div className="tableScroll">
        <table>
          <thead>
            <tr>
              <th>Status</th>
              <th>Call-ID</th>
              <th>Origem</th>
              <th>Destino</th>
              <th>SIP final</th>
              <th>RTP</th>
            </tr>
          </thead>
          <tbody>
            {calls.map((call) => (
              <tr
                className={call.call_id === selectedCallId ? "selected" : ""}
                key={call.call_id}
                onClick={() => onSelect(call.call_id)}
              >
                <td>
                  <span className={`statusPill ${call.status}`}>{call.status}</span>
                </td>
                <td className="mono">{call.call_id}</td>
                <td>{call.from ?? "-"}</td>
                <td>{call.to ?? "-"}</td>
                <td>{call.final_sip_code ? `${call.final_sip_code} ${call.final_reason ?? ""}` : "-"}</td>
                <td>{call.media.rtp_detected ? `${call.media.directions} dir.` : "não"}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </section>
  );
}
