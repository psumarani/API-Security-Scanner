import { useEffect, useMemo, useState } from "react";
import { Link, useNavigate, useSearchParams } from "react-router-dom";
import { Field } from "../components/common/Field";
import { PageHeader } from "../components/common/PageHeader";
import { EmptyState, ErrorBanner, LoadingBlock, Spinner } from "../components/common/States";
import { useAsync } from "../hooks/useAsync";
import { scanService, targetService } from "../services";
import { errorMessage } from "../services/api";
import type { BflaRuleInput, BolaObjectInput, ScanCreate, SpecPreview } from "../types/api";
import { btnPrimary, btnSecondary, card, input } from "../utils/ui";

const NUMBER_FIELDS = [
  { key: "timeout_seconds", label: "Request timeout (s)" },
  { key: "max_requests", label: "Request budget" },
  { key: "max_concurrency", label: "Max concurrency" },
  { key: "max_duration_seconds", label: "Max duration (s)" },
] as const;

const toggle = (list: string[], v: string) => (list.includes(v) ? list.filter((x) => x !== v) : [...list, v]);

export function NewScanPage() {
  const navigate = useNavigate();
  const [params] = useSearchParams();
  const targets = useAsync(() => targetService.list(), []);
  const catalog = useAsync(() => scanService.catalog(), []);
  const [targetId, setTargetId] = useState(params.get("target") ?? "");
  const profiles = useAsync(() => (targetId ? targetService.profiles(targetId) : Promise.resolve([])), [targetId]);

  const [modules, setModules] = useState<string[] | null>(null);
  const [profileIds, setProfileIds] = useState<string[] | null>(null);
  const [limits, setLimits] = useState({ timeout_seconds: 10, max_requests: 300, max_concurrency: 3, max_duration_seconds: 600 });
  const [unsafe, setUnsafe] = useState(false);
  const [sqliParams, setSqliParams] = useState(5);
  const [rlRequests, setRlRequests] = useState(30);
  const [rlPath, setRlPath] = useState("");
  const [bola, setBola] = useState<BolaObjectInput[]>([]);
  const [bfla, setBfla] = useState<BflaRuleInput[]>([]);
  const [confirmed, setConfirmed] = useState(false);
  const [preview, setPreview] = useState<SpecPreview | null>(null);
  const [previewing, setPreviewing] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);

  const target = targets.data?.items.find((t) => t.id === targetId);
  const selModules = modules ?? catalog.data?.modules.filter((m) => m.default_enabled).map((m) => m.id) ?? [];
  const allProfiles = useMemo(() => profiles.data ?? [], [profiles.data]);
  const selProfiles = profileIds ?? allProfiles.map((p) => p.id);

  useEffect(() => { setProfileIds(null); setPreview(null); setBola([]); setBfla([]); }, [targetId]);

  const limitInfo = catalog.data?.limits ?? {};
  const limitErrors = NUMBER_FIELDS.filter(({ key }) => {
    const l = limitInfo[key]; const v = limits[key];
    return !Number.isFinite(v) || (l?.min != null && v < l.min) || (l?.max != null && v > l.max);
  });

  const profileOptions = allProfiles.filter((p) => selProfiles.includes(p.id));
  const bolaOk = bola.every((o) => o.path.startsWith("/") && o.owner);
  const bflaOk = bfla.every((r) => r.path.startsWith("/") && r.forbidden.length > 0);
  const needsBola = selModules.includes("bola") && bola.length === 0;
  const needsBfla = selModules.includes("bfla") && bfla.length === 0;
  const canSubmit = !!target && selModules.length > 0 && confirmed && limitErrors.length === 0 && bolaOk && bflaOk && !submitting;

  const runPreview = async () => {
    setPreviewing(true); setError(null);
    try { setPreview(await targetService.specPreview(targetId)); } catch (e) { setPreview(null); setError(errorMessage(e)); } finally { setPreviewing(false); }
  };

  const submit = async () => {
    if (!canSubmit || !target) return;
    setSubmitting(true); setError(null);
    const body: ScanCreate = {
      target_id: target.id, modules: selModules, auth_profile_ids: selProfiles, authorization_confirmed: true,
      settings: {
        ...limits, allow_unsafe_methods: unsafe, sqli: { max_parameters: sqliParams },
        rate_limit: { requests: rlRequests, concurrency: 5, path: rlPath.trim() || null },
        bola_objects: bola, bfla_rules: bfla,
      },
    };
    try { navigate(`/scans/${(await scanService.create(body)).id}/progress`); } catch (e) { setError(errorMessage(e)); setSubmitting(false); }
  };

  if (targets.loading || catalog.loading) return <LoadingBlock />;
  if (targets.error || catalog.error) return <ErrorBanner message={(targets.error ?? catalog.error)!} onRetry={() => { targets.reload(); catalog.reload(); }} />;
  if (!targets.data?.items.length) return <><PageHeader title="New scan" /><EmptyState title="Add a target first" action={<Link to="/targets" className={btnPrimary}>Go to targets</Link>}>A scan needs an authorized target.</EmptyState></>;

  return (
    <>
      <PageHeader title="New scan" subtitle="Configure scope, modules and safety limits" />
      <div className="space-y-6">
        {error && <ErrorBanner message={error} />}

        <section className={`${card} space-y-4 p-5`} aria-labelledby="s1">
          <h2 id="s1" className="text-lg font-semibold">1. Target and specification</h2>
          <Field id="target" label="Target">
            <select id="target" className={input} value={targetId} onChange={(e) => setTargetId(e.target.value)}>
              <option value="">Select a target…</option>
              {targets.data.items.map((t) => <option key={t.id} value={t.id}>{t.name} — {t.base_url}</option>)}
            </select>
          </Field>
          {target && (
            <>
              <div className="flex flex-wrap items-center gap-3">
                <button className={btnSecondary} onClick={runPreview} disabled={!target.api_spec_url || previewing}>{previewing ? "Importing…" : "Import OpenAPI spec"}</button>
                {!target.api_spec_url && <span className="text-sm text-amber-700">No spec URL on this target; few endpoints will be tested.</span>}
                {previewing && <Spinner label="Fetching" />}
              </div>
              {preview && <p className="text-sm text-emerald-800">Found {preview.endpoint_count} operations in {preview.title ?? "the specification"} ({preview.spec_version}).{preview.base_path_hint && ` Base path ${preview.base_path_hint} will be applied.`}</p>}
            </>
          )}
        </section>

        {target && (
          <>
            <section className={`${card} space-y-3 p-5`} aria-labelledby="s2">
              <h2 id="s2" className="text-lg font-semibold">2. Authentication profiles</h2>
              {profiles.loading ? <Spinner /> : allProfiles.length === 0 ? (
                <p className="text-sm text-slate-600">No profiles. Only anonymous requests will be sent. <Link className="text-emerald-700 underline" to={`/targets/${target.id}`}>Add profiles</Link></p>
              ) : (
                <fieldset><legend className="sr-only">Profiles to use</legend>
                  <div className="flex flex-wrap gap-3">{allProfiles.map((p) => (
                    <label key={p.id} className="flex items-center gap-2 text-sm"><input type="checkbox" checked={selProfiles.includes(p.id)} onChange={() => setProfileIds(toggle(selProfiles, p.id))} />{p.name}{p.role_label && <span className="text-slate-500">({p.role_label})</span>}</label>
                  ))}</div>
                </fieldset>
              )}
            </section>

            <section className={`${card} space-y-3 p-5`} aria-labelledby="s3">
              <h2 id="s3" className="text-lg font-semibold">3. Scanner modules</h2>
              <ul className="space-y-3">
                {catalog.data!.modules.map((m) => (
                  <li key={m.id} className="rounded-md border border-slate-200 p-3">
                    <label className="flex items-start gap-3">
                      <input type="checkbox" className="mt-1" checked={selModules.includes(m.id)} onChange={() => setModules(toggle(selModules, m.id))} />
                      <span><span className="font-medium">{m.name}</span> <span className="text-xs text-slate-500">{m.categories.join(", ")}</span>
                        <span className="block text-sm text-slate-600">{m.description}</span>
                        <span className="block text-xs text-slate-500">Needs: {m.prerequisites.join("; ")}</span></span>
                    </label>
                  </li>
                ))}
              </ul>
              {selModules.includes("rate_limit") && (
                <div className="grid gap-4 rounded-md bg-slate-50 p-3 sm:grid-cols-2">
                  <Field id="rl-req" label="Rate-limit burst size" hint="Bounded burst; stops early on 429 or server errors."><input id="rl-req" type="number" min={5} max={100} className={input} value={rlRequests} onChange={(e) => setRlRequests(Number(e.target.value))} /></Field>
                  <Field id="rl-path" label="Path to probe (optional)" hint="Relative to the base URL, e.g. /api/ping"><input id="rl-path" className={input} value={rlPath} onChange={(e) => setRlPath(e.target.value)} /></Field>
                </div>
              )}
              {selModules.includes("sqli") && <Field id="sqli-n" label="SQL injection: parameters per endpoint"><input id="sqli-n" type="number" min={1} max={10} className={`${input} max-w-32`} value={sqliParams} onChange={(e) => setSqliParams(Number(e.target.value))} /></Field>}

              {selModules.includes("bola") && (
                <div className="rounded-md bg-slate-50 p-3">
                  <h3 className="text-sm font-semibold">Known objects (BOLA)</h3>
                  <p className="mb-2 text-xs text-slate-500">Paths of objects and the profile that owns each. Needs at least two selected profiles.</p>
                  {bola.map((o, i) => (
                    <div key={i} className="mb-2 grid gap-2 sm:grid-cols-[1fr_12rem_auto]">
                      <input aria-label={`Object path ${i + 1}`} placeholder="/api/orders/1" className={input} value={o.path} onChange={(e) => setBola(bola.map((x, j) => (j === i ? { ...x, path: e.target.value } : x)))} />
                      <select aria-label={`Owner ${i + 1}`} className={input} value={o.owner} onChange={(e) => setBola(bola.map((x, j) => (j === i ? { ...x, owner: e.target.value } : x)))}><option value="">Owner…</option>{profileOptions.map((p) => <option key={p.id} value={p.id}>{p.name}</option>)}</select>
                      <button className={btnSecondary} onClick={() => setBola(bola.filter((_, j) => j !== i))}>Remove</button>
                    </div>
                  ))}
                  <button className={btnSecondary} onClick={() => setBola([...bola, { path: "", owner: profileOptions[0]?.id ?? "" }])}>Add object</button>
                  {needsBola && <p className="mt-2 text-xs text-amber-700">No objects configured: this module will be skipped.</p>}
                </div>
              )}

              {selModules.includes("bfla") && (
                <div className="rounded-md bg-slate-50 p-3">
                  <h3 className="text-sm font-semibold">Permission rules (BFLA)</h3>
                  <p className="mb-2 text-xs text-slate-500">Operations and which profiles must NOT be able to call them. Optionally name a profile that is allowed.</p>
                  {bfla.map((r, i) => (
                    <div key={i} className="mb-2 grid gap-2 sm:grid-cols-[6rem_1fr_11rem_11rem_auto]">
                      <select aria-label={`Method ${i + 1}`} className={input} value={r.method} onChange={(e) => setBfla(bfla.map((x, j) => (j === i ? { ...x, method: e.target.value } : x)))}>{["GET", "HEAD", "OPTIONS", "POST", "PUT", "PATCH", "DELETE"].map((m) => <option key={m}>{m}</option>)}</select>
                      <input aria-label={`Rule path ${i + 1}`} placeholder="/api/admin/users" className={input} value={r.path} onChange={(e) => setBfla(bfla.map((x, j) => (j === i ? { ...x, path: e.target.value } : x)))} />
                      <select aria-label={`Forbidden profile ${i + 1}`} className={input} value={r.forbidden[0] ?? ""} onChange={(e) => setBfla(bfla.map((x, j) => (j === i ? { ...x, forbidden: e.target.value ? [e.target.value] : [] } : x)))}><option value="">Forbidden…</option>{profileOptions.map((p) => <option key={p.id} value={p.id}>{p.name}</option>)}</select>
                      <select aria-label={`Allowed profile ${i + 1}`} className={input} value={r.allowed[0] ?? ""} onChange={(e) => setBfla(bfla.map((x, j) => (j === i ? { ...x, allowed: e.target.value ? [e.target.value] : [] } : x)))}><option value="">Allowed (optional)</option>{profileOptions.map((p) => <option key={p.id} value={p.id}>{p.name}</option>)}</select>
                      <button className={btnSecondary} onClick={() => setBfla(bfla.filter((_, j) => j !== i))}>Remove</button>
                    </div>
                  ))}
                  <button className={btnSecondary} onClick={() => setBfla([...bfla, { method: "GET", path: "", allowed: [], forbidden: [] }])}>Add rule</button>
                  {needsBfla && <p className="mt-2 text-xs text-amber-700">No rules configured: this module will be skipped.</p>}
                </div>
              )}
            </section>

            <section className={`${card} space-y-4 p-5`} aria-labelledby="s4">
              <h2 id="s4" className="text-lg font-semibold">4. Safety limits</h2>
              <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
                {NUMBER_FIELDS.map(({ key, label }) => {
                  const l = limitInfo[key]; const bad = limitErrors.some((e) => e.key === key);
                  return (
                    <Field key={key} id={`lim-${key}`} label={label} hint={l ? `Allowed ${l.min}–${l.max}` : undefined} error={bad ? `Must be between ${l?.min} and ${l?.max}` : undefined}>
                      <input id={`lim-${key}`} type="number" className={input} min={l?.min ?? undefined} max={l?.max ?? undefined} value={limits[key]} aria-invalid={bad} onChange={(e) => setLimits({ ...limits, [key]: Number(e.target.value) })} />
                    </Field>
                  );
                })}
              </div>
              <label className="flex items-start gap-2 text-sm"><input type="checkbox" className="mt-1" checked={unsafe} onChange={(e) => setUnsafe(e.target.checked)} /><span>Allow state-changing HTTP methods (only used by BFLA rules you define). Leave off for production systems.</span></label>
            </section>

            <section className={`${card} space-y-3 p-5`} aria-labelledby="s5">
              <h2 id="s5" className="text-lg font-semibold">5. Review and authorize</h2>
              <dl className="grid gap-2 text-sm sm:grid-cols-2">
                <div><dt className="text-slate-500">Authorized origin</dt><dd className="break-all font-mono">{target.base_url}</dd></div>
                <div><dt className="text-slate-500">Specification</dt><dd className="break-all font-mono">{target.api_spec_url ?? "none"}</dd></div>
                <div><dt className="text-slate-500">Modules</dt><dd>{selModules.length} selected</dd></div>
                <div><dt className="text-slate-500">Profiles</dt><dd>{selProfiles.length ? allProfiles.filter((p) => selProfiles.includes(p.id)).map((p) => p.name).join(", ") : "anonymous only"}</dd></div>
                <div><dt className="text-slate-500">Budget</dt><dd>{limits.max_requests} requests · concurrency {limits.max_concurrency} · {limits.max_duration_seconds}s</dd></div>
                {target.allow_local_lab && <div><dt className="text-slate-500">Mode</dt><dd>Local lab (loopback/private allowed for this origin only)</dd></div>}
              </dl>
              <label className="flex items-start gap-2 text-sm font-medium"><input type="checkbox" className="mt-1" checked={confirmed} onChange={(e) => setConfirmed(e.target.checked)} /><span>I confirm that I am authorized to test the scope above and accept that the scan will send real requests to it.</span></label>
              <button className={btnPrimary} disabled={!canSubmit} onClick={submit}>{submitting ? "Starting…" : "Start scan"}</button>
            </section>
          </>
        )}
      </div>
    </>
  );
}
