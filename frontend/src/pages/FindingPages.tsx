import { useEffect, useMemo, useState } from "react";
import { Link, useParams, useSearchParams } from "react-router-dom";
import { ConfidenceBadge, SeverityBadge, StatusBadge } from "../components/common/Badges";
import { PageHeader } from "../components/common/PageHeader";
import { Pagination } from "../components/common/Pagination";
import { EmptyState, ErrorBanner, LoadingBlock } from "../components/common/States";
import { EvidenceList } from "../components/findings/EvidenceList";
import { EMPTY_FILTERS, FindingFilters, type Filters } from "../components/findings/FindingFilters";
import { FindingTable } from "../components/findings/FindingTable";
import { useAsync } from "../hooks/useAsync";
import { scanService } from "../services";
import { errorMessage } from "../services/api";
import { shortId } from "../utils/format";
import { btnSecondary, card, linkClass } from "../utils/ui";

export function FindingsPage() {
  const [params, setParams] = useSearchParams();
  const scanId = params.get("scan") ?? undefined;
  const [filters, setFilters] = useState<Filters>(EMPTY_FILTERS);
  const [debounced, setDebounced] = useState(filters);
  const [offset, setOffset] = useState(0);
  const limit = 20;
  const catalog = useAsync(() => scanService.catalog(), []);
  const categories = useMemo(() => [...(catalog.data?.owasp_coverage.map((c) => c.category) ?? []), "other"], [catalog.data]);

  useEffect(() => { const t = setTimeout(() => { setDebounced(filters); setOffset(0); }, 300); return () => clearTimeout(t); }, [filters]);

  const findings = useAsync(
    () => scanService.findings({ limit, offset, scan_id: scanId, severity: debounced.severity, status: debounced.status, category: debounced.category, search: debounced.search.trim() || undefined }),
    [scanId, debounced, offset],
  );

  return (
    <>
      <PageHeader title="Findings" subtitle={scanId ? <>Scan <Link className={linkClass} to={`/scans/${scanId}`}>#{shortId(scanId)}</Link></> : "Across all your scans"}
        actions={scanId ? <button className={btnSecondary} onClick={() => setParams({})}>Show all scans</button> : undefined} />
      <FindingFilters value={filters} onChange={setFilters} categories={categories} />
      {findings.loading && !findings.data && <LoadingBlock />}
      {findings.error && <ErrorBanner message={findings.error} onRetry={findings.reload} />}
      {findings.data && (findings.data.items.length ? (
        <><FindingTable findings={findings.data.items} showScan={!scanId} /><Pagination total={findings.data.total} limit={limit} offset={offset} onChange={setOffset} /></>
      ) : <EmptyState title="No findings match">Adjust the filters, or run a scan to generate findings.</EmptyState>)}
    </>
  );
}

export function FindingDetailPage() {
  const { id = "" } = useParams();
  const { data: f, loading, error, reload } = useAsync(() => scanService.finding(id), [id]);
  const [err, setErr] = useState<string | null>(null);
  if (loading && !f) return <LoadingBlock />;
  if (error) return <ErrorBanner message={error} onRetry={reload} />;
  if (!f) return null;
  const download = async (format: "json" | "html") => { setErr(null); try { await scanService.downloadReport(f.scan_id, format); } catch (e) { setErr(errorMessage(e)); } };

  return (
    <>
      <PageHeader title={f.title} subtitle={<span className="flex flex-wrap items-center gap-2"><SeverityBadge severity={f.severity} /><StatusBadge status={f.status} /><ConfidenceBadge confidence={f.confidence} /><span className="text-slate-500">{f.category}</span></span>}
        actions={<><Link to={`/scans/${f.scan_id}`} className={btnSecondary}>Scan #{shortId(f.scan_id)}</Link><Link to={`/findings?scan=${f.scan_id}`} className={btnSecondary}>Scan findings</Link></>} />
      <div className="space-y-6">
        {err && <ErrorBanner message={err} />}
        <section className={`${card} p-5`}>
          <dl className="grid gap-4 text-sm sm:grid-cols-2">
            <div><dt className="text-slate-500">Affected endpoint</dt><dd className="font-mono">{f.endpoint ? `${f.endpoint.http_method} ${f.endpoint.path}` : "General (not tied to one endpoint)"}</dd></div>
            <div><dt className="text-slate-500">Target</dt><dd>{f.target_name}</dd></div>
            <div><dt className="text-slate-500">Check</dt><dd className="font-mono">{f.check_id}</dd></div>
            <div><dt className="text-slate-500">Validation status</dt><dd>{f.status === "confirmed" ? "Evidence demonstrates the weakness." : f.status === "potential" ? "Suspicious behaviour; verify manually." : f.status === "informational" ? "Observation or hardening gap, not a demonstrated exploit." : "Test could not be completed."}</dd></div>
          </dl>
        </section>
        <section className={`${card} p-5`}><h2 className="mb-2 text-lg font-semibold">Description</h2><p className="whitespace-pre-line text-sm text-slate-700">{f.description}</p></section>
        <section className={`${card} p-5`}><h2 className="mb-2 text-lg font-semibold">Remediation</h2><p className="whitespace-pre-line text-sm text-slate-700">{f.remediation}</p></section>
        <section><h2 className="mb-2 text-lg font-semibold">Evidence</h2><p className="mb-2 text-xs text-slate-500">Sanitized: credentials are redacted and bodies are summarized or omitted.</p><EvidenceList evidence={f.evidence} /></section>
        <section className="flex flex-wrap gap-2"><button className={btnSecondary} onClick={() => download("html")} disabled={["queued", "running"].includes(f.scan_status)}>Download scan report (HTML)</button><button className={btnSecondary} onClick={() => download("json")} disabled={["queued", "running"].includes(f.scan_status)}>Download scan report (JSON)</button></section>
      </div>
    </>
  );
}
