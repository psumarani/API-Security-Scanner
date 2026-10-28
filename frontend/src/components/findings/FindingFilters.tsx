import { FINDING_STATUSES, SEVERITIES, type FindingStatus, type Severity } from "../../types/api";
import { titleCase } from "../../utils/format";
import { btnSecondary, input } from "../../utils/ui";

export interface Filters { severity: Severity[]; status: FindingStatus[]; search: string; category: string }
export const EMPTY_FILTERS: Filters = { severity: [], status: [], search: "", category: "" };

function toggle<T>(list: T[], value: T): T[] {
  return list.includes(value) ? list.filter((x) => x !== value) : [...list, value];
}

export function FindingFilters({ value, onChange, categories }: { value: Filters; onChange: (f: Filters) => void; categories: string[] }) {
  const active = value.severity.length + value.status.length + (value.search ? 1 : 0) + (value.category ? 1 : 0) > 0;
  const chip = (on: boolean) => `cursor-pointer rounded-full border px-3 py-1 text-xs font-medium ${on ? "border-emerald-600 bg-emerald-600 text-white" : "border-slate-300 bg-white text-slate-700 hover:bg-slate-50"}`;
  return (
    <form role="search" aria-label="Filter findings" onSubmit={(e) => e.preventDefault()} className="mb-4 space-y-3 rounded-lg border border-slate-200 bg-white p-4">
      <div className="grid gap-3 sm:grid-cols-2">
        <div>
          <label htmlFor="f-search" className="mb-1 block text-xs font-medium text-slate-600">Search</label>
          <input id="f-search" className={input} placeholder="Title or description" value={value.search} onChange={(e) => onChange({ ...value, search: e.target.value })} maxLength={100} />
        </div>
        <div>
          <label htmlFor="f-cat" className="mb-1 block text-xs font-medium text-slate-600">OWASP category</label>
          <select id="f-cat" className={input} value={value.category} onChange={(e) => onChange({ ...value, category: e.target.value })}>
            <option value="">All categories</option>
            {categories.map((c) => <option key={c} value={c}>{c}</option>)}
          </select>
        </div>
      </div>
      <fieldset>
        <legend className="mb-1 text-xs font-medium text-slate-600">Severity</legend>
        <div className="flex flex-wrap gap-2">
          {SEVERITIES.map((s) => (
            <label key={s} className={chip(value.severity.includes(s))}>
              <input type="checkbox" className="sr-only" checked={value.severity.includes(s)} onChange={() => onChange({ ...value, severity: toggle(value.severity, s) })} />
              {titleCase(s)}
            </label>
          ))}
        </div>
      </fieldset>
      <fieldset>
        <legend className="mb-1 text-xs font-medium text-slate-600">Validation status</legend>
        <div className="flex flex-wrap gap-2">
          {FINDING_STATUSES.map((s) => (
            <label key={s} className={chip(value.status.includes(s))}>
              <input type="checkbox" className="sr-only" checked={value.status.includes(s)} onChange={() => onChange({ ...value, status: toggle(value.status, s) })} />
              {titleCase(s)}
            </label>
          ))}
        </div>
      </fieldset>
      {active && <button type="button" className={btnSecondary} onClick={() => onChange(EMPTY_FILTERS)}>Clear filters</button>}
    </form>
  );
}
