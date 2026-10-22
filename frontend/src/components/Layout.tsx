import { BookOpen, ChartColumn, Database, ExternalLink, House, Menu, SquareTerminal, X } from "lucide-react";
import { useEffect, useState, type ReactNode } from "react";
import { api } from "../api";
import { hrefFor, type Page } from "../lib/router";
import { AREA, REPOSITORY_URL } from "../lib/project";
import type { Health } from "../types";

const NAV: { page: Page; label: string; icon: ReactNode }[] = [
  { page: "home", label: "Home", icon: <House size={16} aria-hidden /> },
  { page: "playground", label: "SQL Playground", icon: <SquareTerminal size={16} aria-hidden /> },
  { page: "analytics", label: "Analytics", icon: <ChartColumn size={16} aria-hidden /> },
  { page: "docs", label: "Documentation", icon: <BookOpen size={16} aria-hidden /> },
];

function useHealth(): Health | null {
  const [health, setHealth] = useState<Health | null>(null);
  useEffect(() => {
    let alive = true;
    const check = () =>
      api
        .health()
        .then((value) => alive && setHealth(value))
        .catch((error: Error) => alive && setHealth({ database: "down", error: error.message }));
    void check();
    const timer = setInterval(check, 15000);
    return () => {
      alive = false;
      clearInterval(timer);
    };
  }, []);
  return health;
}

function HealthBadge({ health }: { health: Health | null }) {
  if (!health) return <span className="text-xs text-slate-400">checking MariaDB...</span>;
  const up = health.database === "up";
  return (
    <span
      className="inline-flex items-center gap-1.5 rounded-full bg-navy-800 px-2.5 py-1 text-xs text-slate-200"
      title={up ? `${health.server_version} on ${health.host}:${health.port}` : health.error}
    >
      <span className={`h-2 w-2 rounded-full ${up ? "bg-emerald-400" : "bg-red-400"}`} aria-hidden />
      <span className="hidden sm:inline">{up ? `MariaDB ${health.server_version?.split("-")[0]}` : "MariaDB unreachable"}</span>
      <span className="sm:hidden">{up ? "DB" : "DB down"}</span>
    </span>
  );
}

export function Layout({ page, children }: { page: Page; children: ReactNode }) {
  const health = useHealth();
  const [open, setOpen] = useState(false);
  useEffect(() => setOpen(false), [page]);

  return (
    <div className="flex min-h-screen flex-col">
      <header className="sticky top-0 z-20 bg-navy-900 text-white shadow">
        <div className="mx-auto flex h-14 max-w-7xl items-center gap-4 px-4">
          <a href={hrefFor("home")} className="flex items-center gap-2 whitespace-nowrap font-semibold tracking-tight">
            <span className="grid h-8 w-8 place-items-center rounded-lg bg-accent-500/20 text-accent-100">
              <Database size={18} aria-hidden />
            </span>
            <span>
              MariaDB <span className="text-accent-100">Interactive Lab</span>
            </span>
          </a>
          <nav className="ml-6 hidden items-center gap-1 md:flex" aria-label="Main">
            {NAV.map((item) => (
              <a
                key={item.page}
                href={hrefFor(item.page)}
                aria-current={page === item.page ? "page" : undefined}
                className={`flex items-center gap-1.5 rounded-md px-3 py-1.5 text-sm transition-colors ${
                  page === item.page ? "bg-navy-700 text-white" : "text-slate-300 hover:bg-navy-800 hover:text-white"
                }`}
              >
                {item.icon}
                {item.label}
              </a>
            ))}
          </nav>
          <div className="ml-auto flex items-center gap-3">
            <HealthBadge health={health} />
            <a
              href={REPOSITORY_URL}
              target="_blank"
              rel="noreferrer"
              className="hidden items-center gap-1 text-sm text-slate-300 hover:text-white sm:flex"
            >
              GitHub <ExternalLink size={14} aria-hidden />
            </a>
            <button
              type="button"
              className="rounded-md p-1.5 text-slate-200 hover:bg-navy-800 md:hidden"
              onClick={() => setOpen(!open)}
              aria-expanded={open}
              aria-label="Toggle navigation"
            >
              {open ? <X size={20} /> : <Menu size={20} />}
            </button>
          </div>
        </div>
        {open && (
          <nav className="border-t border-navy-800 px-4 py-2 md:hidden" aria-label="Main (mobile)">
            {NAV.map((item) => (
              <a
                key={item.page}
                href={hrefFor(item.page)}
                className={`flex items-center gap-2 rounded-md px-3 py-2 text-sm ${page === item.page ? "bg-navy-700" : "text-slate-300"}`}
              >
                {item.icon}
                {item.label}
              </a>
            ))}
          </nav>
        )}
      </header>

      {health?.database === "down" && (
        <div className="border-b border-red-200 bg-red-50 px-4 py-2 text-center text-sm text-red-800" role="alert">
          {health.error ?? "MariaDB is not reachable."}
        </div>
      )}

      <main className="mx-auto w-full max-w-7xl flex-1 px-4 py-8">{children}</main>

      <footer className="border-t border-slate-200 bg-white">
        <div className="mx-auto flex max-w-7xl flex-col gap-1 px-4 py-4 text-xs text-slate-500 sm:flex-row sm:justify-between">
          <span>
            Area {AREA.number}: {AREA.title} · MariaDB student database projects, 2026-09 · Constructor University
          </span>
          <a href={REPOSITORY_URL} target="_blank" rel="noreferrer" className="hover:text-slate-700">
            {REPOSITORY_URL.replace("https://", "")}
          </a>
        </div>
      </footer>
    </div>
  );
}
