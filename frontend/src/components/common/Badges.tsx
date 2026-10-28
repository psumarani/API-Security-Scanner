import type { Confidence, FindingStatus, ScanStatus, Severity } from "../../types/api";
import { titleCase } from "../../utils/format";

const base = "inline-flex items-center rounded-full px-2 py-0.5 text-xs font-semibold ring-1 ring-inset";

const SEVERITY: Record<Severity, string> = {
  critical: "bg-red-700 text-white ring-red-800",
  high: "bg-orange-600 text-white ring-orange-700",
  medium: "bg-amber-100 text-amber-900 ring-amber-300",
  low: "bg-blue-100 text-blue-900 ring-blue-300",
  info: "bg-slate-100 text-slate-700 ring-slate-300",
};
export const SEVERITY_COLORS: Record<Severity, string> = {
  critical: "#b91c1c", high: "#ea580c", medium: "#d97706", low: "#2563eb", info: "#64748b",
};

const STATUS: Record<FindingStatus, string> = {
  confirmed: "bg-red-50 text-red-800 ring-red-200",
  potential: "bg-amber-50 text-amber-800 ring-amber-200",
  informational: "bg-slate-50 text-slate-700 ring-slate-200",
  inconclusive: "bg-violet-50 text-violet-800 ring-violet-200",
};

const SCAN: Record<ScanStatus, string> = {
  queued: "bg-slate-100 text-slate-700 ring-slate-300",
  running: "bg-blue-50 text-blue-800 ring-blue-200",
  completed: "bg-emerald-50 text-emerald-800 ring-emerald-200",
  failed: "bg-red-50 text-red-800 ring-red-200",
  cancelled: "bg-slate-100 text-slate-600 ring-slate-300",
};

export const SeverityBadge = ({ severity }: { severity: Severity }) => (
  <span className={`${base} ${SEVERITY[severity]}`}>{titleCase(severity)}</span>
);
export const StatusBadge = ({ status }: { status: FindingStatus }) => (
  <span className={`${base} ${STATUS[status]}`}>{titleCase(status)}</span>
);
export const ConfidenceBadge = ({ confidence }: { confidence: Confidence }) => (
  <span className={`${base} bg-white text-slate-700 ring-slate-300`}>Confidence: {confidence}</span>
);
export const ScanStatusBadge = ({ status }: { status: ScanStatus }) => (
  <span className={`${base} ${SCAN[status]}`}>
    {status === "running" && <span className="mr-1.5 h-1.5 w-1.5 animate-pulse rounded-full bg-blue-600" aria-hidden />}
    {titleCase(status)}
  </span>
);
export const SupportBadge = ({ support }: { support: "supported" | "partial" | "unsupported" }) => {
  const cls = {
    supported: "bg-emerald-50 text-emerald-800 ring-emerald-200",
    partial: "bg-amber-50 text-amber-800 ring-amber-200",
    unsupported: "bg-slate-100 text-slate-600 ring-slate-300",
  }[support];
  return <span className={`${base} ${cls}`}>{titleCase(support)}</span>;
};
