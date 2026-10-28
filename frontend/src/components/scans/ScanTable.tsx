import { Link } from "react-router-dom";
import type { Scan } from "../../types/api";
import { formatDate, formatDuration, shortId } from "../../utils/format";
import { linkClass } from "../../utils/ui";
import { ScanStatusBadge } from "../common/Badges";
import { SeverityCounts } from "./SeverityCounts";

export function ScanTable({ scans }: { scans: Scan[] }) {
  return (
    <div className="overflow-x-auto rounded-lg border border-slate-200 bg-white">
      <table className="min-w-full divide-y divide-slate-200 text-sm">
        <caption className="sr-only">Scans</caption>
        <thead className="bg-slate-50 text-left text-xs uppercase tracking-wide text-slate-500">
          <tr>
            <th scope="col" className="px-4 py-2">Scan</th>
            <th scope="col" className="px-4 py-2">Target</th>
            <th scope="col" className="px-4 py-2">Status</th>
            <th scope="col" className="px-4 py-2">Findings</th>
            <th scope="col" className="px-4 py-2">Started</th>
            <th scope="col" className="px-4 py-2">Duration</th>
          </tr>
        </thead>
        <tbody className="divide-y divide-slate-100">
          {scans.map((s) => (
            <tr key={s.id} className="hover:bg-slate-50">
              <td className="px-4 py-2"><Link className={linkClass} to={`/scans/${s.id}`}>#{shortId(s.id)}</Link></td>
              <td className="px-4 py-2">{s.target_name}</td>
              <td className="px-4 py-2">
                <ScanStatusBadge status={s.status} />
                {s.status === "failed" && s.error_summary && <p className="mt-1 max-w-xs truncate text-xs text-red-700" title={s.error_summary}>{s.error_summary}</p>}
              </td>
              <td className="px-4 py-2"><SeverityCounts counts={s.finding_counts} /></td>
              <td className="px-4 py-2 whitespace-nowrap">{formatDate(s.started_at ?? s.created_at)}</td>
              <td className="px-4 py-2">{formatDuration(s.started_at, s.completed_at)}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
