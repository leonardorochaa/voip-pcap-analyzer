import { ChevronDown } from "lucide-react";

export function TechnicalJson({ payload }: { payload: unknown }) {
  return (
    <details className="panel technicalPanel">
      <summary>
        <span>JSON técnico</span>
        <ChevronDown size={18} />
      </summary>
      <pre>{JSON.stringify(payload, null, 2)}</pre>
    </details>
  );
}
