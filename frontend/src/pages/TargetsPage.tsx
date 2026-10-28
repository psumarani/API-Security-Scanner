import { useState } from "react";
import { useForm } from "react-hook-form";
import { Link } from "react-router-dom";
import { z } from "zod";
import { ConfirmDialog } from "../components/common/ConfirmDialog";
import { Field, describedBy } from "../components/common/Field";
import { PageHeader } from "../components/common/PageHeader";
import { EmptyState, ErrorBanner, LoadingBlock, SuccessBanner } from "../components/common/States";
import { useAsync } from "../hooks/useAsync";
import { targetService } from "../services";
import { errorMessage } from "../services/api";
import type { Target } from "../types/api";
import { formatDate } from "../utils/format";
import { btnPrimary, btnSecondary, card, input, linkClass } from "../utils/ui";
import { zodResolver } from "../utils/zod";

const schema = z.object({
  name: z.string().trim().min(1, "Enter a name").max(120),
  base_url: z.string().trim().url("Enter a full URL, e.g. https://api.example.com/v1"),
  api_spec_url: z.string().trim(),
  authorization_note: z.string().max(1000),
  allow_local_lab: z.boolean(),
  authorization_confirmed: z.boolean().refine((v) => v, "You must confirm you are authorized to test this target"),
});
type Values = z.infer<typeof schema>;

export function TargetsPage() {
  const { data, loading, error, reload } = useAsync(() => targetService.list(), []);
  const [showForm, setShowForm] = useState(false);
  const [formError, setFormError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [toDelete, setToDelete] = useState<Target | null>(null);
  const [deleting, setDeleting] = useState(false);
  const { register, handleSubmit, reset, formState: { errors, isSubmitting } } = useForm<Values>({
    resolver: zodResolver(schema),
    defaultValues: { name: "", base_url: "", api_spec_url: "", authorization_note: "", allow_local_lab: false, authorization_confirmed: false },
  });

  const onSubmit = handleSubmit(async (v) => {
    setFormError(null);
    try {
      const t = await targetService.create({ ...v, api_spec_url: v.api_spec_url || null, authorization_note: v.authorization_note || null });
      setNotice(`Target “${t.name}” added.`);
      reset();
      setShowForm(false);
      reload();
    } catch (e) {
      setFormError(errorMessage(e));
    }
  });

  const confirmDelete = async () => {
    if (!toDelete) return;
    setDeleting(true);
    try {
      await targetService.remove(toDelete.id);
      setNotice(`Target “${toDelete.name}” and its scans were deleted.`);
      setToDelete(null);
      reload();
    } catch (e) {
      setFormError(errorMessage(e));
      setToDelete(null);
    } finally {
      setDeleting(false);
    }
  };

  const f = (name: keyof Values) => ({ "aria-invalid": !!errors[name], "aria-describedby": describedBy(name, errors[name]?.message), ...register(name) });

  return (
    <>
      <PageHeader title="Targets" subtitle="APIs you are authorized to assess" actions={<button className={btnPrimary} onClick={() => setShowForm((v) => !v)}>{showForm ? "Close" : "Add target"}</button>} />
      <div className="space-y-4">
        {notice && <SuccessBanner>{notice}</SuccessBanner>}
        {formError && <ErrorBanner message={formError} />}

        {showForm && (
          <form onSubmit={onSubmit} noValidate className={`${card} space-y-4 p-5`}>
            <h2 className="text-lg font-semibold">New target</h2>
            <div className="grid gap-4 sm:grid-cols-2">
              <Field id="name" label="Name" error={errors.name?.message}><input id="name" className={input} {...f("name")} /></Field>
              <Field id="base_url" label="Base URL" error={errors.base_url?.message} hint="Scope is limited to this exact scheme, host and port."><input id="base_url" className={input} placeholder="https://api.example.com/v1" {...f("base_url")} /></Field>
              <Field id="api_spec_url" label="OpenAPI / Swagger URL (optional)" error={errors.api_spec_url?.message} hint="Must be on the same origin as the base URL."><input id="api_spec_url" className={input} placeholder="https://api.example.com/openapi.json" {...f("api_spec_url")} /></Field>
              <Field id="authorization_note" label="Authorization note (optional)" error={errors.authorization_note?.message} hint="For your records, e.g. ticket or contract reference."><input id="authorization_note" className={input} {...f("authorization_note")} /></Field>
            </div>
            <label className="flex items-start gap-2 text-sm">
              <input type="checkbox" className="mt-1" {...register("allow_local_lab")} />
              <span>Local lab target (loopback/private address). Also requires <code>ALLOW_LOCAL_LAB_TARGETS=true</code> on the server.</span>
            </label>
            <div>
              <label className="flex items-start gap-2 text-sm font-medium">
                <input type="checkbox" className="mt-1" aria-invalid={!!errors.authorization_confirmed} {...register("authorization_confirmed")} />
                <span>I own this API or have explicit written permission to security-test it.</span>
              </label>
              {errors.authorization_confirmed && <p role="alert" className="mt-1 text-xs text-red-700">{errors.authorization_confirmed.message}</p>}
            </div>
            <button className={btnPrimary} disabled={isSubmitting}>{isSubmitting ? "Validating scope…" : "Save target"}</button>
          </form>
        )}

        {loading && !data && <LoadingBlock />}
        {error && <ErrorBanner message={error} onRetry={reload} />}
        {data && data.items.length === 0 && !showForm && <EmptyState title="No targets yet" action={<button className={btnPrimary} onClick={() => setShowForm(true)}>Add your first target</button>}>Only add systems you are permitted to test.</EmptyState>}
        {data && data.items.length > 0 && (
          <ul className="grid gap-4 md:grid-cols-2">
            {data.items.map((t) => (
              <li key={t.id} className={`${card} p-4`}>
                <div className="flex items-start justify-between gap-2">
                  <Link to={`/targets/${t.id}`} className={`${linkClass} text-lg font-semibold`}>{t.name}</Link>
                  {t.allow_local_lab && <span className="rounded-full bg-violet-50 px-2 py-0.5 text-xs text-violet-800 ring-1 ring-violet-200">Local lab</span>}
                </div>
                <p className="mt-1 break-all font-mono text-xs text-slate-600">{t.base_url}</p>
                <p className="mt-2 text-xs text-slate-500">Authorized {formatDate(t.authorization_confirmed_at)}</p>
                <div className="mt-4 flex gap-2">
                  <Link to={`/scans/new?target=${t.id}`} className={btnPrimary}>Scan</Link>
                  <Link to={`/targets/${t.id}`} className={btnSecondary}>Details</Link>
                  <button className={`${btnSecondary} text-red-700`} onClick={() => setToDelete(t)}>Delete</button>
                </div>
              </li>
            ))}
          </ul>
        )}
      </div>
      {toDelete && (
        <ConfirmDialog title={`Delete “${toDelete.name}”?`} confirmLabel="Delete" busy={deleting} onConfirm={confirmDelete} onCancel={() => setToDelete(null)}>
          This permanently removes the target, its auth profiles, all scans, findings and evidence. This cannot be undone.
        </ConfirmDialog>
      )}
    </>
  );
}
