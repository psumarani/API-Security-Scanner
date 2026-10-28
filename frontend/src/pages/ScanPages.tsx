import { useState } from "react";
import { Link, useNavigate, useParams, useSearchParams } from "react-router-dom";
import { SeverityChart } from "../components/dashboard/Charts";
import { ConfirmDialog } from "../components/common/ConfirmDialog";
import { PageHeader, StatCard } from "../components/common/PageHeader";
import { ScanStatusBadge } from "../components/common/Badges";
import { Pagination } from "../components/common/Pagination";
import { EmptyState, ErrorBanner, LoadingBlock } from "../components/common/States";
import { FindingTable } from "../components/findings/FindingTable";
import { ModuleProgressList, ScanProgressBar } from "../components/scans/ModuleProgressList";
import { ScanTable } from "../components/scans/ScanTable";
import { useAsync } from "../hooks/useAsync";
import { scanService } from "../services";
import { errorMessage } from "../services/api";
import type { Scan, ScanStatus } from "../types/api";
import { formatDate, formatDuration, shortId, titleCase } from "../utils/format";
import { btnPrimary, btnSecondary, card, input, linkClass } from "../utils/ui";

const ACTIVE: ScanStatus[] = ["queued", "running"];
const isActive = (s: Scan) => ACTIVE.includes(s.status);

export function ScanProgressPage() {
  const { id = "" } = useParams();
  const navigate = useNavigate();
  const scan = useAsync(() => scanService.get(id), [id], { pollWhile: isActive, intervalMs: 1500 });
  const catalog = useAsync(() => scanService.catalog(), []);
  const [confirmCancel, setConfirmCancel] = useState(false);
  const [cancelling, setCancelling] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const cancel = async () => {
    setCancelling(true);
    try { await scanService.cancel(id); scan.reload(); } catch (e) { setError(errorMessage(e)); } finally { setCancelling(false); setConfirmCancel(false); }
  };

  if (scan.loading && !scan.data) return <LoadingBlock />;
  if (scan.error && !scan.data) return <ErrorBanner message={scan.error} onRetry={scan.reload} />;
  const s = scan.data;
  if (!s) return null;

  return (
    <>
      <PageHeader title={`Scan #${shortId(s.id)}`} subtitle={`${s.target_name} · ${s.configuration.scope?.origin ?? ""}`}
        actions={isActive(s) ? <button className={btnSecondary} onClick={() => setConfirmCancel(true)}>Cancel scan</button> : <button className={btnPrimary} onClick={() => navigate(`/scans/${s.id}`)}>View results</button>} />
      <div className="space-y-6">
        {error && <ErrorBanner message={error} />}
        {scan.error && <ErrorBanner message={`Lost connection while updating: ${scan.error}`} />}
        <section className={`${card} space-y-4 p-5`} aria-live="polite">
          <div className="flex items-center justify-between"><ScanStatusBadge status={s.status} /><span className="text-sm text-slate-500">{s.requests_made} requests · {formatDuration(s.started_at, s.completed_at)}</span></div>
          {s.status === "queued" && <p className="text-sm text-slate-600">Waiting for a free scanner slot…</p>}
          <ScanProgressBar scan={s} />
          {s.status === "failed" && <ErrorBanner message={s.error_summary ?? "The scan failed."} />}
          {s.status === "cancelled" && <p className="text-sm text-slate-600">This scan was cancelled. Partial results are available.</p>}
          {s.status === "completed" && <p className="text-sm text-emerald-700">Scan finished with {Object.values(s.finding_counts).reduce((a, b) => a + (b ?? 0), 0)} finding(s).</p>}
        </section>
        <section><h2 className="mb-2 text-lg font-semibold">Modules</h2>{catalog.data && <ModuleProgressList scan={s} modules={catalog.data.modules} />}</section>
      </div>
      {confirmCancel && <ConfirmDialog title="Cancel this scan?" confirmLabel="Cancel scan" busy={cancelling} onConfirm={cancel} onCancel={() => setConfirmCancel(false)}>The scan stops at the next safe point. Findings gathered so far are kept.</ConfirmDialog>}
    </>
  );
}

export function ScanDetailsPage() {
  const { id = "" } = useParams();
  const scan = useAsync(() => scanService.get(id), [id], { pollWhile: isActive });
  const catalog = useAsync(() => scanService.catalog(), []);
  const endpoints = useAsync(() => scanService.endpoints(id), [id]);
  const findings = useAsync(() => scanService.findings({ scan_id: id, limit: 10 }), [id, scan.data?.status]);
  const [err, setErr] = useState<string | null>(null);

  const download = async (format: "json" | "html") => {
    setErr(null);
    try { await scanService.downloadReport(id, format); } catch (e) { setErr(errorMessage(e)); }
  };

  if (scan.loading && !scan.data) return <LoadingBlock />;
  if (scan.error && !scan.data) return <ErrorBanner message={scan.error} onRetry={scan.reload} />;
  const s = scan.data;
  if (!s) return null;
  const finished = !isActive(s);
  const total = Object.values(s.finding_counts).reduce((a, b) => a + (b ?? 0), 0);
  const cfg = s.configuration;

  return (
    <>
      <PageHeader title={`Scan #${shortId(s.id)}`} subtitle={<><Link to={`/targets/${s.target_id}`} className={linkClass}>{s.target_name}</Link> · <ScanStatusBadge status={s.status} /></>}
        actions={<>
          <Link to={`/findings?scan=${s.id}`} className={btnSecondary}>All findings</Link>
          <button className={btnSecondary} disabled={!finished} onClick={() => download("html")}>HTML report</button>
          <button className={btnPrimary} disabled={!finished} onClick={() => download("json")}>JSON report</button>
        </>} />
      <div className="space-y-8">
        {err && <ErrorBanner message={err} />}
        {!finished && <div role="status" className="rounded-md border border-blue-200 bg-blue-50 p-3 text-sm text-blue-900">This scan is still {s.status}. <Link className={linkClass} to={`/scans/${s.id}/progress`}>Watch progress</Link></div>}
        {s.status === "failed" && <ErrorBanner message={s.error_summary ?? "The scan failed."} />}
        {s.status === "cancelled" && <p className="rounded-md bg-slate-100 p-3 text-sm">Cancelled. Results below are partial.</p>}

        <div className="grid grid-cols-2 gap-4 lg:grid-cols-4">
          <StatCard label="Findings" value={total} />
          <StatCard label="Endpoints" value={s.endpoint_count} />
          <StatCard label="Requests" value={s.requests_made} />
          <StatCard label="Duration" value={formatDuration(s.started_at, s.completed_at)} />
        </div>

        <div className="grid gap-6 lg:grid-cols-2">
          <section className={`${card} p-4`}><h2 className="mb-2 text-sm font-semibold">Findings by severity</h2><SeverityChart counts={s.finding_counts} /></section>
          <section className={`${card} p-5`}>
            <h2 className="mb-3 text-sm font-semibold">Scope and configuration</h2>
            <dl className="space-y-2 text-sm">
              <div><dt className="text-slate-500">Authorized origin</dt><dd className="break-all font-mono">{cfg.scope?.origin}</dd></div>
              <div><dt className="text-slate-500">Specification</dt><dd className="break-all font-mono">{cfg.scope?.spec_url ?? "none"}</dd></div>
              <div><dt className="text-slate-500">Profiles</dt><dd>{cfg.auth_profiles?.length ? cfg.auth_profiles.map((p) => `${p.name} (${titleCase(p.auth_type)})`).join(", ") : "anonymous"}</dd></div>
              <div><dt className="text-slate-500">Started / completed</dt><dd>{formatDate(s.started_at)} / {formatDate(s.completed_at)}</dd></div>
              <div><dt className="text-slate-500">Scanner version</dt><dd>{s.scanner_version}</dd></div>
            </dl>
          </section>
        </div>

        <section><h2 className="mb-2 text-lg font-semibold">Module coverage</h2>{catalog.data && <ModuleProgressList scan={s} modules={catalog.data.modules} />}
          {s.progress.notes?.map((n) => <p key={n} className="mt-2 text-xs text-slate-600">{n}</p>)}</section>

        <section>
          <div className="mb-2 flex items-center justify-between"><h2 className="text-lg font-semibold">Top findings</h2>{(findings.data?.total ?? 0) > 10 && <Link to={`/findings?scan=${s.id}`} className={`${linkClass} text-sm`}>View all {findings.data?.total}</Link>}</div>
          {findings.data && findings.data.items.length > 0 ? <FindingTable findings={findings.data.items} showScan={false} /> : <EmptyState title={finished ? "No findings" : "No findings yet"}>{finished ? "No weaknesses were detected by the selected modules. This does not prove the API is secure." : "Findings appear as modules complete."}</EmptyState>}
        </section>

        <section>
          <h2 className="mb-2 text-lg font-semibold">Endpoints ({endpoints.data?.length ?? 0})</h2>
          {endpoints.data && endpoints.data.length > 0 ? (
            <div className="max-h-96 overflow-auto rounded-lg border border-slate-200 bg-white">
              <table className="min-w-full text-sm"><caption className="sr-only">Discovered endpoints</caption>
                <thead className="sticky top-0 bg-slate-50 text-left text-xs uppercase text-slate-500"><tr><th scope="col" className="px-4 py-2">Method</th><th scope="col" className="px-4 py-2">Path</th><th scope="col" className="px-4 py-2">Auth declared</th><th scope="col" className="px-4 py-2">Findings</th></tr></thead>
                <tbody className="divide-y divide-slate-100">{endpoints.data.map((e) => (
                  <tr key={e.id}><td className="px-4 py-1.5 font-mono text-xs">{e.http_method}</td><td className="px-4 py-1.5 font-mono text-xs">{e.path}</td><td className="px-4 py-1.5">{e.authentication_required === null ? "unknown" : e.authentication_required ? "yes" : "no"}</td><td className="px-4 py-1.5">{e.finding_count}</td></tr>
                ))}</tbody></table>
            </div>
          ) : <p className="text-sm text-slate-500">No endpoints were discovered.</p>}
        </section>
      </div>
    </>
  );
}

export function ScanHistoryPage() {
  const [params, setParams] = useSearchParams();
  const status = (params.get("status") as ScanStatus | null) ?? undefined;
  const offset = Number(params.get("offset") ?? 0);
  const limit = 15;
  const scans = useAsync(() => scanService.list({ limit, offset, status }), [status, offset], { pollWhile: (d) => d.items.some(isActive), intervalMs: 3000 });
  const set = (k: string, v: string) => { const p = new URLSearchParams(params); if (v) p.set(k, v); else p.delete(k); if (k !== "offset") p.delete("offset"); setParams(p); };

  return (
    <>
      <PageHeader title="Scan history" actions={<Link to="/scans/new" className={btnPrimary}>New scan</Link>} />
      <div className="mb-4 max-w-xs"><label htmlFor="st" className="mb-1 block text-xs font-medium text-slate-600">Status</label>
        <select id="st" className={input} value={status ?? ""} onChange={(e) => set("status", e.target.value)}><option value="">All</option>{(["queued", "running", "completed", "failed", "cancelled"] as ScanStatus[]).map((s) => <option key={s} value={s}>{titleCase(s)}</option>)}</select></div>
      {scans.loading && !scans.data && <LoadingBlock />}
      {scans.error && <ErrorBanner message={scans.error} onRetry={scans.reload} />}
      {scans.data && (scans.data.items.length ? <><ScanTable scans={scans.data.items} /><Pagination total={scans.data.total} limit={limit} offset={offset} onChange={(o) => set("offset", String(o))} /></> : <EmptyState title="No scans found" action={<Link to="/scans/new" className={btnPrimary}>Start a scan</Link>}>Scans you run will appear here.</EmptyState>)}
    </>
  );
}
