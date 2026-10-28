import { useState } from "react";
import { NavLink, Outlet, useNavigate } from "react-router-dom";
import { useAuth } from "../../hooks/useAuth";

const NAV = [
  { to: "/", label: "Dashboard", end: true },
  { to: "/targets", label: "Targets" },
  { to: "/scans/new", label: "New scan" },
  { to: "/scans", label: "Scan history", end: true },
  { to: "/findings", label: "Findings" },
  { to: "/reports", label: "Reports" },
  { to: "/coverage", label: "Coverage" },
  { to: "/settings", label: "Settings" },
];

export function Layout() {
  const { user, logout } = useAuth();
  const navigate = useNavigate();
  const [open, setOpen] = useState(false);

  const onLogout = async () => {
    await logout();
    navigate("/login");
  };

  return (
    <div className="min-h-screen lg:flex">
      <a href="#main" className="sr-only focus:not-sr-only focus:absolute focus:z-50 focus:bg-white focus:p-2">Skip to content</a>
      <header className="flex items-center justify-between bg-slate-900 px-4 py-3 text-white lg:hidden">
        <span className="font-semibold">API Security Scanner</span>
        <button aria-expanded={open} aria-controls="sidebar" onClick={() => setOpen((v) => !v)} className="rounded px-2 py-1 ring-1 ring-slate-600">Menu</button>
      </header>
      <aside id="sidebar" className={`${open ? "block" : "hidden"} w-full shrink-0 bg-slate-900 text-slate-200 lg:block lg:min-h-screen lg:w-60`}>
        <div className="hidden px-5 py-5 lg:block">
          <p className="text-base font-semibold text-white">API Security Scanner</p>
          <p className="text-xs text-slate-400">OWASP API Top 10 assessments</p>
        </div>
        <nav aria-label="Main" className="flex flex-col gap-0.5 px-3 pb-4">
          {NAV.map((item) => (
            <NavLink
              key={item.to}
              to={item.to}
              end={item.end}
              onClick={() => setOpen(false)}
              className={({ isActive }) => `rounded-md px-3 py-2 text-sm ${isActive ? "bg-emerald-600 text-white" : "hover:bg-slate-800"}`}
            >
              {item.label}
            </NavLink>
          ))}
        </nav>
        <div className="border-t border-slate-800 px-5 py-4 text-sm">
          <p className="truncate font-medium text-white">{user?.username}</p>
          <p className="truncate text-xs text-slate-400">{user?.email}</p>
          <button onClick={onLogout} className="mt-3 text-xs text-emerald-300 hover:underline">Sign out</button>
        </div>
      </aside>
      <main id="main" className="min-w-0 flex-1 p-4 sm:p-6 lg:p-8">
        <div className="mx-auto max-w-6xl"><Outlet /></div>
      </main>
    </div>
  );
}
