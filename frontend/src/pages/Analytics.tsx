import { Activity, Ban, CircleCheck, Database, FlaskConical, KeyRound, Lock, Play, ServerCog, Table2 } from "lucide-react";
import { useCallback, useEffect, useState, type ReactNode } from "react";
import {
  Bar,
  BarChart,
  CartesianGrid,
  Legend,
  Line,
  LineChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import { api, ApiError } from "../api";
import { Badge, Button, Card, CardHeader, Notice, Spinner } from "../components/ui";
import { clampRuns, formatMs } from "../lib/format";
import type { BenchmarkResult, CodesResult, MatrixResult, Scenario, Stats, TimingResult } from "../types";

// Categorical slots in fixed order (validated palette, see src/index.css).
const SERIES = ["var(--color-series-1)", "var(--color-series-2)", "var(--color-series-3)", "var(--color-series-4)"];
const AXIS = { stroke: "#cbd5e1", tick: { fill: "#475569", fontSize: 12 } };
const GRID = <CartesianGrid stroke="#eef2f7" vertical={false} />;
// Legend text wears text ink; only the swatch carries the series color.
const LEGEND = { wrapperStyle: { fontSize: 12 }, formatter: (value: string) => <span style={{ color: "#334155" }}>{value}</span> };
const TOOLTIP_STYLE = { borderRadius: 8, border: "1px solid #e2e8f0", fontSize: 12, boxShadow: "0 4px 12px rgb(15 23 42 / 0.08)" };

function StatCard({ icon, label, value, detail }: { icon: ReactNode; label: string; value: ReactNode; detail: ReactNode }) {
  return (
    <Card className="p-4">
      <p className="flex items-center gap-2 text-xs font-semibold uppercase tracking-wide text-slate-500">
        {icon}
        {label}
      </p>
      <p className="mt-2 text-2xl font-semibold tracking-tight text-slate-900">{value}</p>
      <p className="mt-1 text-xs text-slate-500">{detail}</p>
    </Card>
  );
}

function SummaryCards({ stats, history }: { stats: Stats | null; history: BenchmarkResult[] }) {
  if (!stats) return null;
  const totalRows = stats.tables.reduce((sum, table) => sum + table.rows, 0);
  const people = stats.accounts.filter((account) => !account.is_role);
  const ed25519 = people.filter((account) => account.auth_chain.join() === "ed25519").length;
  const socket = people.filter((account) => account.auth_chain.includes("unix_socket")).map((account) => account.user);
  const roles = stats.accounts.filter((account) => account.is_role && account.user !== "PUBLIC").length;
  const samples = history.reduce((sum, result) => sum + (result.kind === "matrix" ? 24 : result.runs * result.comparison.length), 0);
  return (
    <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
      <StatCard
        icon={<ServerCog size={14} aria-hidden />}
        label="Server"
        value={stats.server.version?.split("-")[0] ?? "?"}
        detail={`${stats.session_tls.version} · ${stats.session_tls.cipher} · require_secure_transport=${stats.server.require_secure_transport}`}
      />
      <StatCard
        icon={<Database size={14} aria-hidden />}
        label="Dataset"
        value={`${totalRows} rows`}
        detail={stats.tables.map((table) => `${table.name} ${table.rows}`).join(" · ")}
      />
      <StatCard
        icon={<KeyRound size={14} aria-hidden />}
        label="Accounts"
        value={`${ed25519} ED25519 logins`}
        detail={`${people.length} accounts, ${roles} roles, ${people.filter((account) => account.locked).length} locked · unix_socket: ${socket.join(", ") || "none"}`}
      />
      <StatCard
        icon={<Activity size={14} aria-hidden />}
        label="Benchmark runs"
        value={history.length}
        detail={history.length ? `${samples} measured operations in this browser session` : "none yet - run one below"}
      />
    </div>
  );
}

function ChartCard({ title, children, note }: { title: string; children: ReactNode; note?: string }) {
  return (
    <Card>
      <CardHeader title={title} />
      <div className="p-4">
        <div className="h-72 w-full">{children}</div>
        {note && <p className="mt-2 text-xs text-slate-500">{note}</p>}
      </div>
    </Card>
  );
}

function MatrixView({ result }: { result: MatrixResult }) {
  return (
    <>
      <ChartCard title="Allowed vs. denied, per role (6 actions each)" note="Hover a bar for the counts; every answer is listed in the table.">
        <ResponsiveContainer>
          <BarChart data={result.comparison} layout="vertical" margin={{ left: 8, right: 24 }} barCategoryGap={14}>
            <CartesianGrid stroke="#eef2f7" horizontal={false} />
            <XAxis type="number" domain={[0, 6]} ticks={[0, 1, 2, 3, 4, 5, 6]} {...AXIS} />
            <YAxis type="category" dataKey="label" width={80} {...AXIS} />
            <Tooltip contentStyle={TOOLTIP_STYLE} cursor={{ fill: "#f1f5f9" }} />
            <Legend {...LEGEND} />
            <Bar dataKey="allowed" name="allowed" stackId="a" fill={SERIES[0]} stroke="#fff" strokeWidth={2} />
            <Bar dataKey="denied" name="denied by MariaDB" stackId="a" fill={SERIES[1]} stroke="#fff" strokeWidth={2} radius={[0, 4, 4, 0]} />
          </BarChart>
        </ResponsiveContainer>
      </ChartCard>
      <Card className="overflow-hidden">
        <CardHeader title="Every answer" icon={<Table2 size={16} className="text-accent-500" aria-hidden />} />
        <div className="max-h-96 overflow-auto">
          <table className="min-w-full text-left text-[13px]">
            <thead className="sticky top-0 bg-slate-50 text-xs uppercase tracking-wide text-slate-500">
              <tr>
                {["Role", "Action", "Expected", "MariaDB answered", "Check", "Why"].map((head) => (
                  <th key={head} className="whitespace-nowrap border-b border-slate-200 px-3 py-2 font-semibold">
                    {head}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {result.cells.map((cell) => (
                <tr key={`${cell.role}-${cell.action}`} className="border-b border-slate-100 align-top">
                  <td className="whitespace-nowrap px-3 py-1.5 font-medium">{cell.role}</td>
                  <td className="px-3 py-1.5">{cell.description}</td>
                  <td className="whitespace-nowrap px-3 py-1.5">{cell.expected}</td>
                  <td className="whitespace-nowrap px-3 py-1.5">
                    {cell.outcome === "allowed" ? (
                      <span className="inline-flex items-center gap-1 text-emerald-800">
                        <CircleCheck size={13} aria-hidden /> allowed{cell.rows !== null ? ` (${cell.rows} rows)` : ""}
                      </span>
                    ) : (
                      <span className="inline-flex items-center gap-1 text-red-800">
                        <Ban size={13} aria-hidden /> denied ({cell.error})
                      </span>
                    )}
                  </td>
                  <td className="px-3 py-1.5">{cell.match ? <Badge tone="green">match</Badge> : <Badge tone="red">differs</Badge>}</td>
                  <td className="px-3 py-1.5 font-mono text-xs text-slate-600">{cell.why}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </Card>
    </>
  );
}

function CodesView({ result }: { result: CodesResult }) {
  const data = result.comparison.map((group) => ({ label: group.label, "error 1045": group.error_1045, "any other code": group.other }));
  return (
    <>
      <ChartCard
        title="Error code of each failed login"
        note="If unknown names ever got a different code (e.g. 1698), an attacker could tell which accounts exist."
      >
        <ResponsiveContainer>
          <BarChart data={data} margin={{ left: 0, right: 16 }} barCategoryGap="30%">
            {GRID}
            <XAxis dataKey="label" {...AXIS} />
            <YAxis allowDecimals={false} {...AXIS} />
            <Tooltip contentStyle={TOOLTIP_STYLE} cursor={{ fill: "#f1f5f9" }} />
            <Legend {...LEGEND} />
            <Bar dataKey="error 1045" stackId="a" fill={SERIES[0]} stroke="#fff" strokeWidth={2} />
            <Bar dataKey="any other code" stackId="a" fill={SERIES[1]} stroke="#fff" strokeWidth={2} radius={[4, 4, 0, 0]} />
          </BarChart>
        </ResponsiveContainer>
      </ChartCard>
      <DataTable
        head={["Attempt", "Attempts", "Error codes seen", "Median time", "p95", "stdev"]}
        rows={result.comparison.map((group) => [
          group.label,
          String(group.attempts),
          Object.entries(group.codes)
            .map(([code, count]) => `${code} × ${count}`)
            .join(", "),
          formatMs(group.timing.median),
          formatMs(group.timing.p95),
          formatMs(group.timing.stdev),
        ])}
      />
    </>
  );
}

function TimingView({ result }: { result: TimingResult }) {
  const labels = result.comparison.map((item) => item.label);
  return (
    <>
      <div className="grid gap-5 xl:grid-cols-2">
        <ChartCard title={`Median time per configuration (${result.runs} runs each)`} note="Hover a bar for p95 and spread; all values are in the table.">
          <ResponsiveContainer>
            <BarChart data={result.comparison} margin={{ left: 0, right: 16 }} barCategoryGap="35%">
              {GRID}
              <XAxis dataKey="label" {...AXIS} />
              <YAxis unit=" ms" width={64} {...AXIS} />
              <Tooltip
                contentStyle={TOOLTIP_STYLE}
                cursor={{ fill: "#f1f5f9" }}
                formatter={(value) => formatMs(Number(value))}
                labelFormatter={(label) => {
                  const item = result.comparison.find((entry) => entry.label === label);
                  return item ? `${label} · p95 ${formatMs(item.p95)} · stdev ${formatMs(item.stdev)}` : String(label);
                }}
              />
              <Bar dataKey="median" name="median" fill={SERIES[0]} radius={[4, 4, 0, 0]} maxBarSize={56} />
            </BarChart>
          </ResponsiveContainer>
        </ChartCard>
        <ChartCard title="Every run, in order" note="Spikes are real (scheduler, Docker networking); that is why the median is reported.">
          <ResponsiveContainer>
            <LineChart data={result.series} margin={{ left: 0, right: 16 }}>
              {GRID}
              <XAxis dataKey="run" {...AXIS} />
              <YAxis unit=" ms" width={64} {...AXIS} />
              <Tooltip contentStyle={TOOLTIP_STYLE} formatter={(value) => formatMs(Number(value))} labelFormatter={(run) => `run ${run}`} />
              <Legend {...LEGEND} />
              {labels.map((label, index) => (
                <Line key={label} type="monotone" dataKey={label} stroke={SERIES[index]} strokeWidth={2} dot={false} activeDot={{ r: 4 }} />
              ))}
            </LineChart>
          </ResponsiveContainer>
        </ChartCard>
      </div>
      <DataTable
        head={["Configuration", "Detail", "Runs", "Median", "Mean", "stdev", "Min", "p95", "Max"]}
        rows={result.comparison.map((item) => [
          item.label,
          String(item.path ?? item.answer ?? [item.negotiated, item.cipher].filter(Boolean).join(" · ") ?? ""),
          String(item.runs),
          formatMs(item.median),
          formatMs(item.mean),
          formatMs(item.stdev),
          formatMs(item.min),
          formatMs(item.p95),
          formatMs(item.max),
        ])}
      />
    </>
  );
}

function DataTable({ head, rows }: { head: string[]; rows: string[][] }) {
  return (
    <Card className="overflow-hidden">
      <CardHeader title="Table view" icon={<Table2 size={16} className="text-accent-500" aria-hidden />} />
      <div className="overflow-x-auto">
        <table className="min-w-full text-left text-[13px]">
          <thead className="bg-slate-50 text-xs uppercase tracking-wide text-slate-500">
            <tr>
              {head.map((cell) => (
                <th key={cell} className="whitespace-nowrap border-b border-slate-200 px-3 py-2 font-semibold">
                  {cell}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {rows.map((row) => (
              <tr key={row[0]} className="border-b border-slate-100">
                {row.map((cell, index) => (
                  <td key={index} className={`whitespace-nowrap px-3 py-1.5 ${index === 0 ? "font-medium" : "font-mono text-slate-700"}`}>
                    {cell}
                  </td>
                ))}
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </Card>
  );
}

function AccountsTable({ stats }: { stats: Stats }) {
  return (
    <Card className="overflow-hidden">
      <CardHeader title="Accounts and roles on this server (mysql.global_priv)" icon={<Lock size={16} className="text-accent-500" aria-hidden />} />
      <div className="overflow-x-auto">
        <table className="min-w-full text-left text-[13px]">
          <thead className="bg-slate-50 text-xs uppercase tracking-wide text-slate-500">
            <tr>
              {["Account / role", "Host", "Authentication", "Locked", "DENY rules"].map((head) => (
                <th key={head} className="whitespace-nowrap border-b border-slate-200 px-3 py-2 font-semibold">
                  {head}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {stats.accounts.map((account) => (
              <tr key={`${account.user}@${account.host}`} className="border-b border-slate-100">
                <td className="whitespace-nowrap px-3 py-1.5 font-mono">
                  {account.user}
                  {account.is_role && <span className="ml-2 font-sans text-xs text-slate-500">role</span>}
                </td>
                <td className="px-3 py-1.5 font-mono text-slate-600">{account.host || "-"}</td>
                <td className="px-3 py-1.5 font-mono text-slate-700">
                  {account.is_role ? "-" : account.auth_chain.join(" OR ")}
                </td>
                <td className="px-3 py-1.5">{account.is_role ? "-" : account.locked ? "yes" : "no"}</td>
                <td className="px-3 py-1.5">{account.denies ? <Badge tone="red">{account.denies}</Badge> : "-"}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <p className="px-4 py-2.5 text-xs text-slate-500">
        Read live by the lab's temporary administrator. The demo accounts are created locked; the lab unlocks them with
        random passwords that exist only in the backend's memory. The lab's own harness account is not listed.
      </p>
    </Card>
  );
}

export default function Analytics() {
  const [stats, setStats] = useState<Stats | null>(null);
  const [statsError, setStatsError] = useState<string | null>(null);
  const [scenarioList, setScenarioList] = useState<Scenario[]>([]);
  const [scenario, setScenario] = useState("access-matrix");
  const [runs, setRuns] = useState(30);
  const [running, setRunning] = useState(false);
  const [result, setResult] = useState<BenchmarkResult | null>(null);
  const [error, setError] = useState<ApiError | null>(null);
  const [history, setHistory] = useState<BenchmarkResult[]>([]);

  const loadStats = useCallback(() => {
    api
      .stats()
      .then((value) => {
        setStats(value);
        setStatsError(null);
      })
      .catch((reason: Error) => setStatsError(reason.message));
  }, []);

  useEffect(() => {
    loadStats();
    api
      .scenarios()
      .then((value) => setScenarioList(value.scenarios))
      .catch(() => setScenarioList([]));
  }, [loadStats]);

  const current = scenarioList.find((item) => item.id === scenario);

  const runBenchmark = async () => {
    setRunning(true);
    setError(null);
    try {
      const value = await api.benchmark(scenario, clampRuns(runs));
      setResult(value);
      setHistory((items) => [...items, value]);
      loadStats();
    } catch (reason) {
      setError(reason instanceof ApiError ? reason : new ApiError(String(reason), 0));
    } finally {
      setRunning(false);
    }
  };

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold tracking-tight text-slate-900">Analytics</h1>
        <p className="mt-1 max-w-3xl text-sm text-slate-600">
          Live measurements of the access-control setup on your MariaDB server. Nothing on this page is precomputed or
          stored: each benchmark runs now, and its method is printed with the result.
        </p>
      </div>

      {statsError && (
        <Notice tone="error" title="Server statistics are unavailable">
          {statsError}
        </Notice>
      )}
      {!stats && !statsError && <Spinner label="Reading server statistics" />}
      <SummaryCards stats={stats} history={history} />

      <Card>
        <CardHeader title="Benchmark scenario" icon={<FlaskConical size={16} className="text-accent-500" aria-hidden />} />
        <div className="flex flex-wrap items-end gap-4 p-4">
          <label className="flex min-w-64 flex-1 flex-col gap-1 text-sm">
            <span className="text-xs font-semibold uppercase tracking-wide text-slate-500">Scenario</span>
            <select
              value={scenario}
              onChange={(event) => setScenario(event.target.value)}
              className="rounded-lg border border-slate-300 bg-white px-3 py-2 text-sm focus:border-accent-500 focus:outline-none focus:ring-2 focus:ring-accent-100"
            >
              {scenarioList.map((item) => (
                <option key={item.id} value={item.id}>
                  {item.title}
                </option>
              ))}
            </select>
          </label>
          <label className="flex w-32 flex-col gap-1 text-sm">
            <span className="text-xs font-semibold uppercase tracking-wide text-slate-500">Runs</span>
            <input
              type="number"
              min={5}
              max={200}
              value={runs}
              disabled={current ? !current.repeatable : false}
              onChange={(event) => setRuns(Number(event.target.value))}
              className="rounded-lg border border-slate-300 px-3 py-2 text-sm focus:border-accent-500 focus:outline-none focus:ring-2 focus:ring-accent-100 disabled:bg-slate-100 disabled:text-slate-400"
            />
          </label>
          <Button variant="primary" onClick={runBenchmark} disabled={running || !scenarioList.length}>
            <Play size={15} aria-hidden /> {running ? "Running..." : "Run benchmark"}
          </Button>
          {current && <p className="basis-full text-sm text-slate-600">{current.description}</p>}
        </div>
      </Card>

      <div className="space-y-5" aria-live="polite">
        {running && <Spinner label="Measuring on the server (this can take a few seconds)" />}
        {error && (
          <Notice tone="error" title={error.databaseDown ? "MariaDB or the lab backend is unavailable" : "The benchmark failed"}>
            {error.message}
          </Notice>
        )}
        {result && (
          <div className={`space-y-5 transition-opacity ${running ? "opacity-50" : ""}`}>
            <Card className="p-4">
              <p className="text-xs font-semibold uppercase tracking-wide text-slate-500">Result · {result.title}</p>
              <p className="mt-1 text-lg font-semibold text-slate-900">{result.headline}</p>
              <p className="mt-2 text-sm text-slate-600">
                <strong className="font-medium text-slate-700">Method:</strong> {result.method}
              </p>
              <p className="mt-1 text-xs text-slate-500">
                Observed on {result.environment.server_version} at {result.environment.host}, {result.finished_at} ·{" "}
                {result.environment.client}. Single machine, not a controlled lab: compare medians, not single runs.
              </p>
            </Card>
            {result.kind === "matrix" && <MatrixView result={result} />}
            {result.kind === "codes" && <CodesView result={result} />}
            {result.kind === "timing" && <TimingView result={result} />}
          </div>
        )}
      </div>

      {stats && <AccountsTable stats={stats} />}
    </div>
  );
}
