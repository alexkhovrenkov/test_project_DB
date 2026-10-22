import { Ban, CircleCheck, Columns3, Lightbulb, Play, RotateCcw, SquareTerminal, TriangleAlert } from "lucide-react";
import { useEffect, useMemo, useState } from "react";
import { api, ApiError } from "../api";
import { ResultPanel } from "../components/ResultPanel";
import { SqlEditor } from "../components/SqlEditor";
import { Badge, Button, Card, CardHeader, CopyButton, Notice, Spinner } from "../components/ui";
import { describeExpectation, describeOutcome, formatMs } from "../lib/format";
import { ROLE_INFO } from "../lib/project";
import type { Example, ExamplesResponse, QueryResult, Role } from "../types";

const ROLES = Object.keys(ROLE_INFO) as Role[];

function RolePicker({ role, onChange }: { role: Role; onChange: (role: Role) => void }) {
  return (
    <div role="radiogroup" aria-label="Run as" className="inline-flex flex-wrap rounded-lg border border-slate-200 bg-slate-50 p-0.5">
      {ROLES.map((name) => (
        <button
          key={name}
          type="button"
          role="radio"
          aria-checked={role === name}
          onClick={() => onChange(name)}
          title={`${ROLE_INFO[name].account} (${ROLE_INFO[name].role})`}
          className={`rounded-md px-3 py-1.5 text-sm font-medium transition-colors ${
            role === name ? "bg-white text-accent-700 shadow-sm ring-1 ring-slate-200" : "text-slate-600 hover:text-slate-900"
          }`}
        >
          {ROLE_INFO[name].label}
        </button>
      ))}
    </div>
  );
}

function ExampleList({
  data,
  selected,
  onSelect,
}: {
  data: ExamplesResponse;
  selected: string | null;
  onSelect: (example: Example) => void;
}) {
  return (
    <nav aria-label="Example queries" className="max-h-72 overflow-y-auto p-2 lg:max-h-[calc(100vh-11rem)]">
      {data.categories.map((category) => (
        <div key={category.id} className="mb-3">
          <p className="px-2 pb-1 pt-2 text-[11px] font-semibold uppercase tracking-wide text-slate-500">{category.title}</p>
          {data.examples
            .filter((example) => example.category === category.id)
            .map((example) => (
              <button
                key={example.id}
                type="button"
                onClick={() => onSelect(example)}
                aria-current={selected === example.id ? "true" : undefined}
                className={`mb-0.5 w-full rounded-md px-2.5 py-2 text-left text-sm transition-colors ${
                  selected === example.id ? "bg-accent-50 text-accent-700 ring-1 ring-accent-100" : "text-slate-700 hover:bg-slate-100"
                }`}
              >
                <span className="block leading-snug">{example.title}</span>
                <span className="mt-0.5 flex items-center gap-1.5 text-xs text-slate-500">
                  {ROLE_INFO[example.role].label}
                  <span aria-hidden>·</span>
                  {example.expect.outcome === "allowed" ? (
                    <span className="text-emerald-700">allowed</span>
                  ) : (
                    <span className={example.expect.outcome === "denied" ? "text-red-700" : "text-amber-800"}>
                      {example.expect.outcome} {example.expect.error}
                    </span>
                  )}
                </span>
              </button>
            ))}
        </div>
      ))}
    </nav>
  );
}

function Explanation({ example }: { example: Example }) {
  const rows: [string, string][] = [
    ["What it does", example.what],
    ["MariaDB feature", example.feature],
    ["Why it matters", example.why],
    ["What to observe", example.observe],
  ];
  return (
    <dl className="grid gap-x-6 gap-y-3 text-sm sm:grid-cols-2">
      {rows.map(([term, text]) => (
        <div key={term}>
          <dt className="text-xs font-semibold uppercase tracking-wide text-slate-500">{term}</dt>
          <dd className={`mt-0.5 leading-relaxed text-slate-700 ${term === "MariaDB feature" ? "font-mono text-[13px]" : ""}`}>{text}</dd>
        </div>
      ))}
    </dl>
  );
}

function CompareStrip({ results }: { results: Partial<Record<Role, QueryResult | string>> }) {
  return (
    <div className="grid gap-2 sm:grid-cols-2 lg:grid-cols-4">
      {ROLES.map((role) => {
        const value = results[role];
        const icon =
          value === undefined ? null : typeof value === "string" ? (
            <TriangleAlert size={15} className="shrink-0 text-amber-700" aria-hidden />
          ) : value.outcome === "allowed" ? (
            <CircleCheck size={15} className="shrink-0 text-emerald-700" aria-hidden />
          ) : value.outcome === "denied" ? (
            <Ban size={15} className="shrink-0 text-red-700" aria-hidden />
          ) : (
            <TriangleAlert size={15} className="shrink-0 text-amber-700" aria-hidden />
          );
        return (
          <div key={role} className="rounded-lg border border-slate-200 bg-white px-3 py-2.5">
            <p className="flex items-center gap-1.5 text-sm font-semibold text-slate-800">
              {icon}
              {ROLE_INFO[role].label}
              <span className="font-normal text-slate-400">{ROLE_INFO[role].account}</span>
            </p>
            <p className="mt-1 text-xs text-slate-600">
              {value === undefined ? (
                <Spinner label="running" />
              ) : typeof value === "string" ? (
                value
              ) : (
                <>
                  {describeOutcome(value)} · {formatMs(value.elapsed_ms)}
                </>
              )}
            </p>
          </div>
        );
      })}
    </div>
  );
}

export default function Playground() {
  const [data, setData] = useState<ExamplesResponse | null>(null);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [selected, setSelected] = useState<Example | null>(null);
  const [role, setRole] = useState<Role>("student");
  const [sql, setSql] = useState("");
  const [running, setRunning] = useState(false);
  const [result, setResult] = useState<QueryResult | null>(null);
  const [runError, setRunError] = useState<ApiError | null>(null);
  const [compare, setCompare] = useState<Partial<Record<Role, QueryResult | string>> | null>(null);

  const select = (example: Example) => {
    setSelected(example);
    setRole(example.role);
    setSql(example.sql);
    setResult(null);
    setRunError(null);
    setCompare(null);
  };

  useEffect(() => {
    api
      .examples()
      .then((response) => {
        setData(response);
        if (response.examples.length) select(response.examples[0]);
      })
      .catch((error: Error) => setLoadError(error.message));
  }, []);

  // The documented expectation applies only while the example is unchanged.
  const pristine = useMemo(
    () => selected !== null && selected.sql === sql && selected.role === role,
    [selected, sql, role],
  );

  const run = async () => {
    if (running || !sql.trim()) return;
    setRunning(true);
    setRunError(null);
    setCompare(null);
    try {
      setResult(await api.query(role, sql));
    } catch (error) {
      setResult(null);
      setRunError(error instanceof ApiError ? error : new ApiError(String(error), 0));
    } finally {
      setRunning(false);
    }
  };

  const runAll = async () => {
    if (running || !sql.trim()) return;
    setRunning(true);
    setRunError(null);
    setCompare({});
    for (const name of ROLES) {
      try {
        const answer = await api.query(name, sql);
        setCompare((current) => ({ ...current, [name]: answer }));
      } catch (error) {
        setCompare((current) => ({ ...current, [name]: error instanceof Error ? error.message : String(error) }));
      }
    }
    setRunning(false);
  };

  if (loadError) {
    return (
      <Notice tone="error" title="The examples could not be loaded">
        {loadError}
      </Notice>
    );
  }
  if (!data) return <Spinner label="Loading the examples" />;

  return (
    <div className="space-y-5">
      <div>
        <h1 className="text-2xl font-bold tracking-tight text-slate-900">SQL Playground</h1>
        <p className="mt-1 max-w-3xl text-sm text-slate-600">
          Every statement runs on the real MariaDB 13.1 server, as the account you pick, over verified TLS with ED25519. The
          app contains no permission checks: rows and refusals both come from MariaDB. Writes run inside a transaction that is
          always rolled back. Limits: one statement, {data.limits.timeout_seconds} s, {data.limits.max_rows} rows.
        </p>
      </div>

      <div className="grid gap-5 lg:grid-cols-[300px_1fr]">
        <Card className="h-fit lg:sticky lg:top-20">
          <CardHeader title="Example queries" icon={<Lightbulb size={16} className="text-accent-500" aria-hidden />} />
          <ExampleList data={data} selected={selected?.id ?? null} onSelect={select} />
        </Card>

        <div className="min-w-0 space-y-5">
          <Card>
            <CardHeader
              title={selected?.title ?? "SQL editor"}
              icon={<SquareTerminal size={16} className="text-accent-500" aria-hidden />}
              action={
                selected && (
                  <Badge tone={pristine ? "blue" : "slate"}>
                    {pristine ? `Documented: ${describeExpectation(selected.expect)}` : "edited"}
                  </Badge>
                )
              }
            />
            <div className="space-y-4 p-4">
              {selected && <Explanation example={selected} />}

              <div className="flex flex-wrap items-center justify-between gap-3 border-t border-slate-100 pt-4">
                <div className="flex flex-wrap items-center gap-2">
                  <span className="text-xs font-semibold uppercase tracking-wide text-slate-500">Run as</span>
                  <RolePicker role={role} onChange={setRole} />
                </div>
                <span className="font-mono text-xs text-slate-500">
                  {ROLE_INFO[role].account} → {ROLE_INFO[role].role}
                </span>
              </div>

              <SqlEditor value={sql} onChange={setSql} onRun={run} />

              <div className="flex flex-wrap items-center gap-2">
                <Button variant="primary" onClick={run} disabled={running || !sql.trim()}>
                  <Play size={15} aria-hidden /> {running && !compare ? "Running..." : "Run query"}
                </Button>
                <Button onClick={runAll} disabled={running || !sql.trim()} title="Run the same statement as each of the four accounts">
                  <Columns3 size={15} aria-hidden /> Compare all roles
                </Button>
                <Button
                  variant="ghost"
                  onClick={() => selected && select(selected)}
                  disabled={!selected || pristine}
                  title="Restore the example's SQL and role"
                >
                  <RotateCcw size={15} aria-hidden /> Reset
                </Button>
                <CopyButton text={sql} label="Copy SQL" />
                <span className="ml-auto hidden text-xs text-slate-400 sm:inline">Ctrl/⌘ + Enter runs the query</span>
              </div>
            </div>
          </Card>

          <Card>
            <CardHeader title="Results" icon={<Columns3 size={16} className="text-accent-500" aria-hidden />} />
            <div className="p-4" aria-live="polite">
              {running && !compare && <Spinner label="MariaDB is answering" />}
              {runError && (
                <Notice tone="error" title={runError.databaseDown ? "MariaDB or the lab backend is unavailable" : "The lab refused the request"}>
                  {runError.message}
                </Notice>
              )}
              {compare && (
                <div className="space-y-2">
                  <p className="text-sm text-slate-600">The same statement, sent once per account:</p>
                  <CompareStrip results={compare} />
                </div>
              )}
              {!compare && result && <ResultPanel result={result} expect={pristine ? selected?.expect : undefined} />}
              {!running && !runError && !result && !compare && (
                <p className="text-sm text-slate-500">Press Run query to send the statement to MariaDB.</p>
              )}
            </div>
          </Card>
        </div>
      </div>
    </div>
  );
}
