import type { ModuleInfo, Scan } from "../../types/api";
import { titleCase } from "../../utils/format";

const TONE: Record<string, string> = {
  completed: "text-emerald-700", running: "text-blue-700", failed: "text-red-700",
  cancelled: "text-slate-500", pending: "text-slate-500", skipped: "text-slate-500",
};

export function ScanProgressBar({ scan }: { scan: Scan }) {
  const done = scan.status === "completed";
  const pct = done ? 100 : Math.min(100, Math.max(0, scan.progress.percent ?? 0));
  return (
    <div>
      <div className="flex justify-between text-xs text-slate-600">
        <span>{titleCase(scan.progress.stage ?? scan.status)}{scan.progress.current_module ? ` · ${scan.progress.current_module}` : ""}</span>
        <span>{pct}%</span>
      </div>
      <div className="mt-1 h-2 overflow-hidden rounded-full bg-slate-200" role="progressbar" aria-valuenow={pct} aria-valuemin={0} aria-valuemax={100} aria-label="Scan progress">
        <div className="h-full bg-emerald-600 transition-all" style={{ width: `${pct}%` }} />
      </div>
    </div>
  );
}

export function ModuleProgressList({ scan, modules }: { scan: Scan; modules: ModuleInfo[] }) {
  const ids = scan.configuration.modules ?? [];
  const names = new Map(modules.map((m) => [m.id, m.name]));
  return (
    <ul className="divide-y divide-slate-100 rounded-lg border border-slate-200 bg-white">
      {ids.map((id) => {
        const m = scan.progress.modules?.[id];
        const status = m?.status ?? "pending";
        return (
          <li key={id} className="px-4 py-3 text-sm">
            <div className="flex flex-wrap items-center justify-between gap-2">
              <span className="font-medium">{names.get(id) ?? id}</span>
              <span className={`text-xs font-semibold ${TONE[status] ?? ""}`}>{titleCase(status)}</span>
            </div>
            <p className="text-xs text-slate-500">{m?.findings ?? 0} finding(s) · {m?.requests ?? 0} request(s)</p>
            {m?.notes?.map((n, i) => <p key={`n${i}`} className="mt-1 text-xs text-slate-600">{n}</p>)}
            {m?.inconclusive?.map((n, i) => <p key={`i${i}`} className="mt-1 text-xs text-violet-700">Inconclusive: {n}</p>)}
          </li>
        );
      })}
    </ul>
  );
}
