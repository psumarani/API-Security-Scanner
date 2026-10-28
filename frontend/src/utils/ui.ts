// Shared Tailwind class strings so controls look and behave consistently.
export const btn =
  "inline-flex items-center justify-center gap-2 rounded-md px-3.5 py-2 text-sm font-medium transition-colors disabled:cursor-not-allowed disabled:opacity-50";
export const btnPrimary = `${btn} bg-emerald-600 text-white hover:bg-emerald-700`;
export const btnSecondary = `${btn} border border-slate-300 bg-white text-slate-700 hover:bg-slate-50`;
export const btnDanger = `${btn} bg-red-600 text-white hover:bg-red-700`;
export const input =
  "block w-full rounded-md border border-slate-300 bg-white px-3 py-2 text-sm shadow-sm placeholder:text-slate-400 focus:border-emerald-600 disabled:bg-slate-100";
export const card = "rounded-lg border border-slate-200 bg-white shadow-sm";
export const linkClass = "text-emerald-700 underline-offset-2 hover:underline";
