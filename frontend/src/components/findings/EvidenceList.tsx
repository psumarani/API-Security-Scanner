import type { Evidence } from "../../types/api";
import { formatDate } from "../../utils/format";

export function EvidenceList({ evidence }: { evidence: Evidence[] }) {
  if (evidence.length === 0) return <p className="text-sm text-slate-500">No evidence was recorded for this finding.</p>;
  return (
    <ol className="space-y-3">
      {evidence.map((e, i) => (
        <li key={e.id} className="rounded-md border border-slate-200 bg-slate-50 p-3">
          <p className="mb-2 text-xs font-semibold text-slate-600">Evidence {i + 1} · {formatDate(e.observed_at)}{e.response_status !== null && ` · HTTP ${e.response_status}`}</p>
          <p className="text-xs font-medium text-slate-500">Request</p>
          <pre className="mb-2 whitespace-pre-wrap break-words rounded bg-white p-2 font-mono text-xs">{e.request_summary}</pre>
          <p className="text-xs font-medium text-slate-500">Response</p>
          <pre className="whitespace-pre-wrap break-words rounded bg-white p-2 font-mono text-xs">{e.response_summary}</pre>
        </li>
      ))}
    </ol>
  );
}
