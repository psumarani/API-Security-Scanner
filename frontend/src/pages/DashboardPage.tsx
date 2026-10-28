import { Link } from "react-router-dom";
import { SeverityChart, StatusChart } from "../components/dashboard/Charts";
import { LoadingBlock, ErrorBanner, EmptyState } from "../components/common/States";
import { PageHeader, StatCard } from "../components/common/PageHeader";
import { FindingTable } from "../components/findings/FindingTable";
import { ScanTable } from "../components/scans/ScanTable";
import { useAsync } from "../hooks/useAsync";
import { scanService } from "../services";
import { formatDate, shortId } from "../utils/format";
import { btnPrimary, card, linkClass } from "../utils/ui";

export function DashboardPage() {
  const { data, loading, error, reload } = useAsync(() => scanService.dashboard(), [], {
    pollWhile: (d) => d.running_scans > 0,
    intervalMs: 3000,
  });

  return (
    <>
      <PageHeader title="Dashboard" subtitle="Overview of your assessments" actions={<Link to="/scans/new" className={btnPrimary}>New scan</Link>} />
      {loading && !data && <LoadingBlock />}
      {error && <ErrorBanner message={error} onRetry={reload} />}
      {data && (
        <div className="space-y-8">
          <div className="grid grid-cols-2 gap-4 lg:grid-cols-5">
            <StatCard label="Total scans" value={data.total_scans} />
            <StatCard label="Completed" value={data.completed_scans} tone="good" />
            <StatCard label="In progress" value={data.running_scans} />
            <StatCard label="Failed" value={data.failed_scans} tone={data.failed_scans ? "bad" : "default"} />
            <StatCard label="Findings" value={data.total_findings} />
          </div>

          <div className="grid gap-6 lg:grid-cols-2">
            <section className={`${card} p-4`}>
              <h2 className="mb-2 text-sm font-semibold">Findings by severity</h2>
              <SeverityChart counts={data.findings_by_severity} />
            </section>
            <section className={`${card} p-4`}>
              <h2 className="mb-2 text-sm font-semibold">Findings by validation status</h2>
              <StatusChart counts={data.findings_by_status} />
            </section>
          </div>

          {data.recent_failures.length > 0 && (
            <section aria-labelledby="fail-h">
              <h2 id="fail-h" className="mb-2 text-lg font-semibold">Recent failures</h2>
              <ul className="divide-y divide-red-100 rounded-lg border border-red-200 bg-red-50">
                {data.recent_failures.map((f) => (
                  <li key={f.scan_id} className="p-3 text-sm">
                    <Link className={linkClass} to={`/scans/${f.scan_id}`}>#{shortId(f.scan_id)} · {f.target_name}</Link>
                    <span className="ml-2 text-xs text-slate-500">{formatDate(f.completed_at)}</span>
                    <p className="text-red-800">{f.error_summary ?? "No error details recorded."}</p>
                  </li>
                ))}
              </ul>
            </section>
          )}

          <section aria-labelledby="rs-h">
            <div className="mb-2 flex items-center justify-between"><h2 id="rs-h" className="text-lg font-semibold">Recent scans</h2><Link to="/scans" className={`${linkClass} text-sm`}>View all</Link></div>
            {data.recent_scans.length ? <ScanTable scans={data.recent_scans} /> : <EmptyState title="No scans yet" action={<Link to="/scans/new" className={btnPrimary}>Run your first scan</Link>}>Add a target, then start an assessment.</EmptyState>}
          </section>

          <section aria-labelledby="rf-h">
            <div className="mb-2 flex items-center justify-between"><h2 id="rf-h" className="text-lg font-semibold">Recent findings</h2><Link to="/findings" className={`${linkClass} text-sm`}>View all</Link></div>
            {data.recent_findings.length ? <FindingTable findings={data.recent_findings} /> : <EmptyState title="No confirmed or potential findings">Findings appear here after a scan completes.</EmptyState>}
          </section>
        </div>
      )}
    </>
  );
}
