import { useEffect, useRef, type ReactNode } from "react";
import { btnDanger, btnSecondary } from "../../utils/ui";

export function ConfirmDialog({ title, children, confirmLabel = "Confirm", busy, onConfirm, onCancel }: {
  title: string; children: ReactNode; confirmLabel?: string; busy?: boolean; onConfirm: () => void; onCancel: () => void;
}) {
  const cancelRef = useRef<HTMLButtonElement>(null);
  useEffect(() => {
    cancelRef.current?.focus();
    const onKey = (e: KeyboardEvent) => e.key === "Escape" && onCancel();
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [onCancel]);
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-slate-900/50 p-4">
      <div role="alertdialog" aria-modal="true" aria-labelledby="dlg-title" className="w-full max-w-md rounded-lg bg-white p-6 shadow-xl">
        <h2 id="dlg-title" className="text-lg font-semibold">{title}</h2>
        <div className="mt-2 text-sm text-slate-600">{children}</div>
        <div className="mt-6 flex justify-end gap-3">
          <button ref={cancelRef} className={btnSecondary} onClick={onCancel} disabled={busy}>Cancel</button>
          <button className={btnDanger} onClick={onConfirm} disabled={busy}>{busy ? "Working…" : confirmLabel}</button>
        </div>
      </div>
    </div>
  );
}
