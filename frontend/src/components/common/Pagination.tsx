import { btnSecondary } from "../../utils/ui";

export function Pagination({ total, limit, offset, onChange }: { total: number; limit: number; offset: number; onChange: (offset: number) => void }) {
  if (total <= limit) return null;
  const page = Math.floor(offset / limit) + 1;
  const pages = Math.ceil(total / limit);
  return (
    <nav aria-label="Pagination" className="flex items-center justify-between pt-4 text-sm text-slate-600">
      <span>Showing {offset + 1}–{Math.min(offset + limit, total)} of {total}</span>
      <div className="flex items-center gap-2">
        <button className={btnSecondary} disabled={offset === 0} onClick={() => onChange(Math.max(0, offset - limit))}>Previous</button>
        <span aria-live="polite">Page {page} of {pages}</span>
        <button className={btnSecondary} disabled={offset + limit >= total} onClick={() => onChange(offset + limit)}>Next</button>
      </div>
    </nav>
  );
}
