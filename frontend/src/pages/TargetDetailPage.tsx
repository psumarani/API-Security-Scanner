import { useState } from "react";
import { useForm } from "react-hook-form";
import { Link, useParams } from "react-router-dom";
import { z } from "zod";
import { ConfirmDialog } from "../components/common/ConfirmDialog";
import { Field, describedBy } from "../components/common/Field";
import { PageHeader } from "../components/common/PageHeader";
import { EmptyState, ErrorBanner, LoadingBlock, Spinner, SuccessBanner } from "../components/common/States";
import { useAsync } from "../hooks/useAsync";
import { targetService } from "../services";
import { errorMessage } from "../services/api";
import type { AuthConfigInput, AuthProfile, SpecPreview } from "../types/api";
import { formatDate, titleCase } from "../utils/format";
import { btnPrimary, btnSecondary, card, input } from "../utils/ui";
import { zodResolver } from "../utils/zod";

const schema = z.object({
  name: z.string().trim().min(1, "Enter a name").max(120),
  role_label: z.string().trim().regex(/^([A-Za-z0-9][A-Za-z0-9_.-]{0,63})?$/, "Letters, digits, '.', '_' or '-'"),
  type: z.enum(["none", "bearer", "api_key", "test_account"]),
  token: z.string(),
  key_name: z.string(),
  key_location: z.enum(["header", "query"]),
  key_value: z.string(),
  username: z.string(),
  password: z.string(),
  login_path: z.string(),
}).superRefine((v, ctx) => {
  const need = (cond: boolean, path: string, message: string) => cond && ctx.addIssue({ code: "custom", path: [path], message });
  if (v.type === "bearer") need(!v.token.trim() || /\s/.test(v.token), "token", "Enter the token without spaces");
  if (v.type === "api_key") {
    need(!/^[A-Za-z0-9-_.]{1,64}$/.test(v.key_name), "key_name", "Enter a header or parameter name");
    need(!v.key_value, "key_value", "Enter the key value");
  }
  if (v.type === "test_account") {
    need(!v.username, "username", "Enter the username");
    need(!v.password, "password", "Enter the password");
    need(!!v.login_path && !v.login_path.startsWith("/"), "login_path", "Must start with '/'");
  }
});
type Values = z.infer<typeof schema>;

function toConfig(v: Values): AuthConfigInput {
  switch (v.type) {
    case "bearer": return { type: "bearer", token: v.token.trim() };
    case "api_key": return { type: "api_key", name: v.key_name, location: v.key_location, value: v.key_value };
    case "test_account": return { type: "test_account", username: v.username, password: v.password, login_path: v.login_path || null };
    default: return { type: "none" };
  }
}

export function TargetDetailPage() {
  const { id = "" } = useParams();
  const target = useAsync(() => targetService.get(id), [id]);
  const profiles = useAsync(() => targetService.profiles(id), [id]);
  const [preview, setPreview] = useState<SpecPreview | null>(null);
  const [previewing, setPreviewing] = useState(false);
  const [msg, setMsg] = useState<{ ok: boolean; text: string } | null>(null);
  const [toDelete, setToDelete] = useState<AuthProfile | null>(null);
  const { register, handleSubmit, watch, reset, formState: { errors, isSubmitting } } = useForm<Values>({
    resolver: zodResolver(schema),
    defaultValues: { name: "", role_label: "", type: "bearer", token: "", key_name: "X-API-Key", key_location: "header", key_value: "", username: "", password: "", login_path: "" },
  });
  const type = watch("type");

  const runPreview = async () => {
    setPreviewing(true);
    setMsg(null);
    try { setPreview(await targetService.specPreview(id)); } catch (e) { setPreview(null); setMsg({ ok: false, text: errorMessage(e) }); } finally { setPreviewing(false); }
  };

  const onSubmit = handleSubmit(async (v) => {
    setMsg(null);
    try {
      await targetService.createProfile(id, { name: v.name, role_label: v.role_label || null, config: toConfig(v) });
      reset();
      setMsg({ ok: true, text: "Auth profile saved. Credentials are encrypted and cannot be viewed again." });
      profiles.reload();
    } catch (e) { setMsg({ ok: false, text: errorMessage(e) }); }
  });

  const removeProfile = async () => {
    if (!toDelete) return;
    try { await targetService.removeProfile(id, toDelete.id); profiles.reload(); } catch (e) { setMsg({ ok: false, text: errorMessage(e) }); }
    setToDelete(null);
  };

  const f = (name: keyof Values) => ({ "aria-invalid": !!errors[name], "aria-describedby": describedBy(name, errors[name]?.message), ...register(name) });

  if (target.loading && !target.data) return <LoadingBlock />;
  if (target.error) return <ErrorBanner message={target.error} onRetry={target.reload} />;
  const t = target.data;
  if (!t) return null;

  return (
    <>
      <PageHeader title={t.name} subtitle={<span className="font-mono">{t.base_url}</span>} actions={<><Link to="/targets" className={btnSecondary}>All targets</Link><Link to={`/scans/new?target=${t.id}`} className={btnPrimary}>Start scan</Link></>} />
      <div className="space-y-8">
        <section className={`${card} p-5`} aria-labelledby="scope-h">
          <h2 id="scope-h" className="mb-3 text-lg font-semibold">Authorized scope</h2>
          <dl className="grid gap-x-8 gap-y-2 text-sm sm:grid-cols-2">
            <div><dt className="text-slate-500">Origin and base path</dt><dd className="break-all font-mono">{t.base_url}</dd></div>
            <div><dt className="text-slate-500">Specification</dt><dd className="break-all font-mono">{t.api_spec_url ?? "None"}</dd></div>
            <div><dt className="text-slate-500">Authorization confirmed</dt><dd>{formatDate(t.authorization_confirmed_at)}</dd></div>
            <div><dt className="text-slate-500">Local lab mode</dt><dd>{t.allow_local_lab ? "Enabled" : "Off"}</dd></div>
            {t.authorization_note && <div className="sm:col-span-2"><dt className="text-slate-500">Note</dt><dd>{t.authorization_note}</dd></div>}
          </dl>
          <p className="mt-3 text-xs text-slate-500">Requests are restricted to this exact origin. Redirects elsewhere and private or metadata addresses are blocked.</p>
        </section>

        <section className={`${card} p-5`} aria-labelledby="spec-h">
          <div className="flex items-center justify-between gap-3">
            <h2 id="spec-h" className="text-lg font-semibold">API specification</h2>
            <button className={btnSecondary} onClick={runPreview} disabled={!t.api_spec_url || previewing}>{previewing ? "Importing…" : "Import and preview"}</button>
          </div>
          {!t.api_spec_url && <p className="mt-2 text-sm text-slate-500">This target has no specification URL, so endpoints cannot be discovered automatically.</p>}
          {previewing && <div className="mt-3"><Spinner label="Fetching specification" /></div>}
          {preview && (
            <div className="mt-4">
              <p className="text-sm"><strong>{preview.title ?? "Untitled API"}</strong> · {preview.spec_version} · {preview.endpoint_count} operations · schemes: {Object.keys(preview.security_schemes).join(", ") || "none declared"}</p>
              {preview.warnings.map((w) => <p key={w} className="mt-1 text-xs text-amber-700">{w}</p>)}
              <div className="mt-3 max-h-72 overflow-auto rounded border border-slate-200">
                <table className="min-w-full text-xs">
                  <thead className="sticky top-0 bg-slate-50 text-left text-slate-500"><tr><th className="px-3 py-1.5">Method</th><th className="px-3 py-1.5">Path</th><th className="px-3 py-1.5">Auth</th></tr></thead>
                  <tbody className="divide-y divide-slate-100">
                    {preview.endpoints.map((e) => (
                      <tr key={`${e.method}${e.path}`}><td className="px-3 py-1.5 font-mono">{e.method}</td><td className="px-3 py-1.5 font-mono">{e.path}{e.deprecated && " (deprecated)"}</td><td className="px-3 py-1.5">{e.authentication_required === null ? "unknown" : e.authentication_required ? "required" : "none"}</td></tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}
        </section>

        <section aria-labelledby="prof-h">
          <h2 id="prof-h" className="mb-1 text-lg font-semibold">Authentication profiles for this API</h2>
          <p className="mb-3 text-sm text-slate-500">Credentials for the API under test (separate from your scanner login). Use several accounts or roles for BOLA and BFLA checks.</p>
          {msg && (msg.ok ? <SuccessBanner>{msg.text}</SuccessBanner> : <ErrorBanner message={msg.text} />)}
          {profiles.loading && !profiles.data && <Spinner />}
          {profiles.data && profiles.data.length === 0 && <EmptyState title="No profiles yet">Without credentials only anonymous checks can run.</EmptyState>}
          {profiles.data && profiles.data.length > 0 && (
            <ul className="mb-4 divide-y divide-slate-100 rounded-lg border border-slate-200 bg-white">
              {profiles.data.map((p) => (
                <li key={p.id} className="flex items-center justify-between gap-3 px-4 py-3 text-sm">
                  <span><strong>{p.name}</strong> <span className="text-slate-500">· {titleCase(p.auth_type)}{p.role_label && ` · ${p.role_label}`}</span></span>
                  <button className={`${btnSecondary} text-red-700`} onClick={() => setToDelete(p)}>Remove</button>
                </li>
              ))}
            </ul>
          )}

          <form onSubmit={onSubmit} noValidate className={`${card} mt-4 space-y-4 p-5`}>
            <h3 className="font-semibold">Add a profile</h3>
            <div className="grid gap-4 sm:grid-cols-3">
              <Field id="p-name" label="Name" error={errors.name?.message}><input id="p-name" className={input} {...f("name")} /></Field>
              <Field id="p-role" label="Role label (optional)" error={errors.role_label?.message} hint="e.g. user_a, user_b, admin"><input id="p-role" className={input} {...f("role_label")} /></Field>
              <Field id="p-type" label="Type"><select id="p-type" className={input} {...register("type")}><option value="bearer">Bearer token</option><option value="api_key">API key</option><option value="test_account">Test account (login)</option><option value="none">None (anonymous)</option></select></Field>
            </div>
            {type === "bearer" && <Field id="p-token" label="Token" error={errors.token?.message}><input id="p-token" type="password" autoComplete="off" className={input} {...f("token")} /></Field>}
            {type === "api_key" && (
              <div className="grid gap-4 sm:grid-cols-3">
                <Field id="p-kn" label="Name" error={errors.key_name?.message}><input id="p-kn" className={input} {...f("key_name")} /></Field>
                <Field id="p-kl" label="Sent in"><select id="p-kl" className={input} {...register("key_location")}><option value="header">Header</option><option value="query">Query parameter</option></select></Field>
                <Field id="p-kv" label="Value" error={errors.key_value?.message}><input id="p-kv" type="password" autoComplete="off" className={input} {...f("key_value")} /></Field>
              </div>
            )}
            {type === "test_account" && (
              <div className="grid gap-4 sm:grid-cols-3">
                <Field id="p-u" label="Username" error={errors.username?.message}><input id="p-u" autoComplete="off" className={input} {...f("username")} /></Field>
                <Field id="p-pw" label="Password" error={errors.password?.message}><input id="p-pw" type="password" autoComplete="new-password" className={input} {...f("password")} /></Field>
                <Field id="p-lp" label="Login path (optional)" error={errors.login_path?.message} hint="POST path that returns an access_token"><input id="p-lp" placeholder="/auth/login" className={input} {...f("login_path")} /></Field>
              </div>
            )}
            <button className={btnPrimary} disabled={isSubmitting}>{isSubmitting ? "Saving…" : "Save profile"}</button>
          </form>
        </section>
      </div>
      {toDelete && <ConfirmDialog title={`Remove “${toDelete.name}”?`} confirmLabel="Remove" onConfirm={removeProfile} onCancel={() => setToDelete(null)}>The stored credentials are deleted. Existing scans keep their results.</ConfirmDialog>}
    </>
  );
}
