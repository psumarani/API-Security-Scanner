import type { ReactNode } from "react";
import { btnSecondary } from "../../utils/ui";

export function Spinner({ label = "Loading" }: { label?: string }) {
  return (
    <span role="status" className="inline-flex items-center gap-2 text-sm text-slate-600">
      <span className="h-4 w-4 animate-spin rounded-full border-2 border-slate-300 border-t-emerald-600" aria-hidden />
      {label}…
    </span>
  );
}

export const LoadingBlock = ({ label }: { label?: string }) => (
  <div className="flex justify-center py-16"><Spinner label={label} /></div>
);

export function ErrorBanner({ message, onRetry }: { message: string; onRetry?: () => void }) {
  return (
    <div role="alert" className="flex items-start justify-between gap-4 rounded-md border border-red-200 bg-red-50 p-3 text-sm text-red-800">
      <span>{message}</span>
      {onRetry && <button className={`${btnSecondary} !py-1`} onClick={onRetry}>Retry</button>}
    </div>
  );
}

export const SuccessBanner = ({ children }: { children: ReactNode }) => (
  <div role="status" className="rounded-md border border-emerald-200 bg-emerald-50 p-3 text-sm text-emerald-800">{children}</div>
);

export function EmptyState({ title, children, action }: { title: string; children?: ReactNode; action?: ReactNode }) {
  return (
    <div className="rounded-lg border border-dashed border-slate-300 bg-white px-6 py-12 text-center">
      <h3 className="text-base font-semibold text-slate-800">{title}</h3>
      {children && <p className="mx-auto mt-1 max-w-md text-sm text-slate-500">{children}</p>}
      {action && <div className="mt-4">{action}</div>}
    </div>
  );
}
