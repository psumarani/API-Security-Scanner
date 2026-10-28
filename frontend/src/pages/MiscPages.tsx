import { useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { ScanStatusBadge, SupportBadge } from "../components/common/Badges";
import { ConfirmDialog } from "../components/common/ConfirmDialog";
import { PageHeader } from "../components/common/PageHeader";
import { Pagination } from "../components/common/Pagination";
import { EmptyState, ErrorBanner, LoadingBlock, SuccessBanner } from "../components/common/States";
import { SeverityCounts } from "../components/scans/SeverityCounts";
import { useAuth } from "../hooks/useAuth";
import { useAsync } from "../hooks/useAsync";
import { authService, scanService } from "../services";
import { errorMessage } from "../services/api";
import { formatDate, shortId } from "../utils/format";
import { btnPrimary, btnSecondary, card, linkClass } from "../utils/ui";

export function ReportsPage() {
  const [offset, setOffset] = useState(0);
  const limit = 15;
  const scans = useAsync(() => scanService.list({ limit, offset }), [offset]);
  const [busy, setBusy] = useState<string | null>(null);
  const [err, setErr] = useState<string | null>(null);

  const download = async (id: string, format: "json" | "html") => {
    setBusy(`${id}${format}`); setErr(null);
    try { await scanService.downloadReport(id, format); } catch (e) { setErr(errorMessage(e)); } finally { setBusy(null); }
  };

  return (
    <>
      <PageHeader title="Reports" subtitle="Download evidence-backed reports for finished scans" />
      <section className={`${card} mb-6 p-5 text-sm text-slate-600`}>
        <h2 className="mb-1 text-base font-semibold text-slate-900">What a report contains</h2>
        Scan and target identifiers, authorized scope and configuration, module coverage, severity summary, endpoint-level findings with sanitized evidence and confidence, remediation guidance, inconclusive tests and scanner limitations. Credentials and full response bodies are never included; all untrusted text is HTML-escaped.
      </section>
      {err && <div className="mb-4"><ErrorBanner message={err} /></div>}
      {scans.loading && !scans.data && <LoadingBlock />}
      {scans.error && <ErrorBanner message={scans.error} onRetry={scans.reload} />}
      {scans.data && (scans.data.items.length ? (
        <>
          <div className="overflow-x-auto rounded-lg border border-slate-200 bg-white">
            <table className="min-w-full divide-y divide-slate-200 text-sm"><caption className="sr-only">Scan reports</caption>
              <thead className="bg-slate-50 text-left text-xs uppercase text-slate-500"><tr><th scope="col" className="px-4 py-2">Scan</th><th scope="col" className="px-4 py-2">Target</th><th scope="col" className="px-4 py-2">Status</th><th scope="col" className="px-4 py-2">Findings</th><th scope="col" className="px-4 py-2">Date</th><th scope="col" className="px-4 py-2"><span className="sr-only">Downloads</span></th></tr></thead>
              <tbody className="divide-y divide-slate-100">{scans.data.items.map((s) => {
                const ready = !["queued", "running"].includes(s.status);
                return (
                  <tr key={s.id}><td className="px-4 py-2"><Link className={linkClass} to={`/scans/${s.id}`}>#{shortId(s.id)}</Link></td><td className="px-4 py-2">{s.target_name}</td><td className="px-4 py-2"><ScanStatusBadge status={s.status} /></td><td className="px-4 py-2"><SeverityCounts counts={s.finding_counts} /></td><td className="px-4 py-2">{formatDate(s.created_at)}</td>
                    <td className="px-4 py-2 whitespace-nowrap"><button className={`${btnSecondary} mr-2`} disabled={!ready || busy === `${s.id}html`} onClick={() => download(s.id, "html")}>HTML</button><button className={btnSecondary} disabled={!ready || busy === `${s.id}json`} onClick={() => download(s.id, "json")}>JSON</button></td></tr>
                );
              })}</tbody></table>
          </div>
          <Pagination total={scans.data.total} limit={limit} offset={offset} onChange={setOffset} />
        </>
      ) : <EmptyState title="No reports yet" action={<Link className={btnPrimary} to="/scans/new">Start a scan</Link>}>Reports are generated from finished scans.</EmptyState>)}
    </>
  );
}

export function CoveragePage() {
  const catalog = useAsync(() => scanService.catalog(), []);
  if (catalog.loading && !catalog.data) return <LoadingBlock />;
  if (catalog.error) return <ErrorBanner message={catalog.error} onRetry={catalog.reload} />;
  const c = catalog.data;
  if (!c) return null;
  return (
    <>
      <PageHeader title="Scanner coverage" subtitle={`Scanner version ${c.scanner_version} · OWASP API Security Top 10 (2023)`} />
      <p className="mb-6 rounded-md border border-amber-200 bg-amber-50 p-3 text-sm text-amber-900">Categories are not claimed as covered just because they are listed. Unsupported categories are marked and produce no results rather than false positives.</p>
      <div className="space-y-4">
        {c.owasp_coverage.map((cat) => (
          <section key={cat.category} className={`${card} p-5`}>
            <div className="flex flex-wrap items-center justify-between gap-2"><h2 className="font-semibold">{cat.category} · {cat.title}</h2><SupportBadge support={cat.support} /></div>
            <dl className="mt-3 grid gap-3 text-sm sm:grid-cols-2">
              <div><dt className="text-slate-500">Automation</dt><dd>{cat.automation}</dd></div>
              <div><dt className="text-slate-500">Modules</dt><dd>{cat.modules.length ? cat.modules.join(", ") : "None"}</dd></div>
              <div><dt className="text-slate-500">Prerequisites</dt><dd>{cat.prerequisites}</dd></div>
              <div><dt className="text-slate-500">Evidence</dt><dd>{cat.evidence}</dd></div>
              <div><dt className="text-slate-500">How a finding is validated</dt><dd>{cat.validation}</dd></div>
              <div><dt className="text-slate-500">Known limitations</dt><dd>{cat.limitations}</dd></div>
            </dl>
          </section>
        ))}
      </div>
    </>
  );
}

export function SettingsPage() {
  const { user, logout } = useAuth();
  const navigate = useNavigate();
  const sessions = useAsync(() => authService.sessions(), []);
  const [msg, setMsg] = useState<string | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [revoking, setRevoking] = useState<string | null>(null);
  const [confirmOut, setConfirmOut] = useState(false);

  const revoke = async (id: string, current: boolean) => {
    setErr(null); setMsg(null);
    try {
      await authService.revokeSession(id);
      if (current) { await logout(); navigate("/login"); return; }
      setMsg("Session signed out."); sessions.reload();
    } catch (e) { setErr(errorMessage(e)); } finally { setRevoking(null); }
  };

  return (
    <>
      <PageHeader title="Settings" />
      <div className="space-y-8">
        <section className={`${card} p-5`}>
          <h2 className="mb-3 text-lg font-semibold">Account</h2>
          <dl className="grid gap-3 text-sm sm:grid-cols-3"><div><dt className="text-slate-500">Username</dt><dd>{user?.username}</dd></div><div><dt className="text-slate-500">Email</dt><dd>{user?.email}</dd></div><div><dt className="text-slate-500">Member since</dt><dd>{formatDate(user?.created_at)}</dd></div></dl>
          <button className={`${btnSecondary} mt-4`} onClick={() => setConfirmOut(true)}>Sign out</button>
        </section>
        <section aria-labelledby="sess-h">
          <h2 id="sess-h" className="mb-1 text-lg font-semibold">Active sessions</h2>
          <p className="mb-3 text-sm text-slate-500">Each sign-in creates a session you can revoke. Revoked sessions stop working immediately.</p>
          {msg && <SuccessBanner>{msg}</SuccessBanner>}{err && <ErrorBanner message={err} />}
          {sessions.loading && !sessions.data && <LoadingBlock />}
          {sessions.error && <ErrorBanner message={sessions.error} onRetry={sessions.reload} />}
          {sessions.data && (
            <ul className="divide-y divide-slate-100 rounded-lg border border-slate-200 bg-white">
              {sessions.data.map((s) => (
                <li key={s.id} className="flex flex-wrap items-center justify-between gap-3 px-4 py-3 text-sm">
                  <span><strong>{s.current ? "This session" : "Other session"}</strong><span className="block text-xs text-slate-500">Signed in {formatDate(s.created_at)} · expires {formatDate(s.expires_at)}</span></span>
                  <button className={btnSecondary} disabled={revoking === s.id} onClick={() => { setRevoking(s.id); void revoke(s.id, s.current); }}>{s.current ? "Sign out" : "Revoke"}</button>
                </li>
              ))}
            </ul>
          )}
        </section>
      </div>
      {confirmOut && <ConfirmDialog title="Sign out?" confirmLabel="Sign out" onConfirm={async () => { await logout(); navigate("/login"); }} onCancel={() => setConfirmOut(false)}>You will need to sign in again.</ConfirmDialog>}
    </>
  );
}

export function NotFoundPage() {
  return <EmptyState title="Page not found" action={<Link to="/" className={btnPrimary}>Back to dashboard</Link>}>The page you are looking for does not exist.</EmptyState>;
}
