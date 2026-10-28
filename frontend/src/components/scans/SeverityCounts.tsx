import { SEVERITIES, type Severity } from "../../types/api";
import { SeverityBadge } from "../common/Badges";

export function SeverityCounts({ counts }: { counts: Partial<Record<Severity, number>> }) {
  const present = SEVERITIES.filter((s) => (counts[s] ?? 0) > 0);
  if (present.length === 0) return <span className="text-slate-400">None</span>;
  return (
    <span className="flex flex-wrap gap-1">
      {present.map((s) => (
        <span key={s} className="inline-flex items-center gap-1"><SeverityBadge severity={s} /><span className="text-xs text-slate-600">{counts[s]}</span></span>
      ))}
    </span>
  );
}
