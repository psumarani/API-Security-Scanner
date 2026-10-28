import { Link } from "react-router-dom";
import type { Finding } from "../../types/api";
import { shortId } from "../../utils/format";
import { linkClass } from "../../utils/ui";
import { ConfidenceBadge, SeverityBadge, StatusBadge } from "../common/Badges";

export function FindingTable({ findings, showScan = true }: { findings: Finding[]; showScan?: boolean }) {
  return (
    <div className="overflow-x-auto rounded-lg border border-slate-200 bg-white">
      <table className="min-w-full divide-y divide-slate-200 text-sm">
        <caption className="sr-only">Findings</caption>
        <thead className="bg-slate-50 text-left text-xs uppercase tracking-wide text-slate-500">
          <tr>
            <th scope="col" className="px-4 py-2">Severity</th>
            <th scope="col" className="px-4 py-2">Finding</th>
            <th scope="col" className="px-4 py-2">Endpoint</th>
            <th scope="col" className="px-4 py-2">Validation</th>
            {showScan && <th scope="col" className="px-4 py-2">Scan</th>}
          </tr>
        </thead>
        <tbody className="divide-y divide-slate-100">
          {findings.map((f) => (
            <tr key={f.id} className="align-top hover:bg-slate-50">
              <td className="px-4 py-2"><SeverityBadge severity={f.severity} /></td>
              <td className="px-4 py-2">
                <Link to={`/findings/${f.id}`} className={`${linkClass} font-medium`}>{f.title}</Link>
                <p className="text-xs text-slate-500">{f.category}</p>
              </td>
              <td className="px-4 py-2 font-mono text-xs">{f.endpoint ? `${f.endpoint.http_method} ${f.endpoint.path}` : <span className="font-sans text-slate-400">General</span>}</td>
              <td className="px-4 py-2"><div className="flex flex-col items-start gap-1"><StatusBadge status={f.status} /><ConfidenceBadge confidence={f.confidence} /></div></td>
              {showScan && <td className="px-4 py-2"><Link to={`/scans/${f.scan_id}`} className={linkClass}>#{shortId(f.scan_id)}</Link>{f.target_name && <p className="text-xs text-slate-500">{f.target_name}</p>}</td>}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
