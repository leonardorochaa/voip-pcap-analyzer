import { ShieldAlert, Wrench } from "lucide-react";
import type { CallAnalysis } from "../types";

export function DiagnosisPanel({ call }: { call: CallAnalysis }) {
  return (
    <section className="diagnosisGrid">
      <article className={`panel diagnosis severity-${call.diagnosis.severity}`}>
        <div className="panelTitleWithIcon">
          <ShieldAlert size={20} />
          <h2>Diagnóstico</h2>
        </div>
        <p>{call.diagnosis.probable_cause}</p>
        {call.ended_by && <span className="muted">Encerrada por {call.ended_by}</span>}
        {call.diagnosis.evidence.length > 0 && (
          <ul className="evidenceList">
            {call.diagnosis.evidence.map((item) => (
              <li key={item}>{item}</li>
            ))}
          </ul>
        )}
      </article>
      <article className="panel diagnosis">
        <div className="panelTitleWithIcon">
          <Wrench size={20} />
          <h2>Resolução sugerida</h2>
        </div>
        <p>{call.diagnosis.resolution}</p>
        {call.diagnosis.suggested_checks.length > 0 && (
          <ul className="evidenceList">
            {call.diagnosis.suggested_checks.map((item) => (
              <li key={item}>{item}</li>
            ))}
          </ul>
        )}
      </article>
    </section>
  );
}
