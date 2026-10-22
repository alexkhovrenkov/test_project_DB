// Shapes of the JSON returned by app/lab_server.py (see app/lab.py).

export type Role = "student" | "professor" | "finance" | "admin";
export type Outcome = "allowed" | "denied" | "error";

export interface Expectation {
  outcome: Outcome;
  rows?: number;
  error?: number;
}

export interface Example {
  id: string;
  category: string;
  title: string;
  role: Role;
  sql: string;
  feature: string;
  what: string;
  why: string;
  observe: string;
  expect: Expectation;
}

export interface ExamplesResponse {
  categories: { id: string; title: string }[];
  examples: Example[];
  roles: { role: Role; account: string }[];
  limits: { max_rows: number; timeout_seconds: number };
}

export interface MariaDBError {
  code: number | null;
  message: string;
  outcome: Outcome;
  hint: string | null;
}

export interface QueryResult {
  ok: boolean;
  role: Role;
  account: string;
  active_role: string | null;
  kind: "read" | "write";
  outcome: Outcome;
  elapsed_ms: number;
  columns?: string[];
  rows?: (string | number | boolean | null)[][];
  row_count?: number;
  affected_rows?: number | null;
  truncated?: boolean;
  rolled_back?: boolean;
  error?: MariaDBError;
}

export interface Health {
  database: "up" | "down";
  server_version?: string;
  server_comment?: string;
  host?: string;
  port?: number;
  error?: string;
}

export interface Stats {
  server: Record<string, string>;
  tables: { name: string; rows: number }[];
  accounts: {
    user: string;
    host: string;
    plugin: string | null;
    locked: boolean;
    is_role: boolean;
    denies: number;
    auth_chain: string[];
  }[];
  plugins: { name: string; status: string; type: string }[];
  session_tls: { version: string | null; cipher: string | null; verified: boolean; ca: string };
}

export interface Scenario {
  id: string;
  title: string;
  description: string;
  repeatable: boolean;
}

export interface TimingSummary {
  runs: number;
  median: number;
  mean: number;
  stdev: number;
  min: number;
  max: number;
  p95: number;
}

export interface BenchmarkBase {
  scenario: string;
  title: string;
  runs: number;
  headline: string;
  method: string;
  finished_at: string;
  environment: { server_version?: string; client: string; host: string };
}

export interface MatrixResult extends BenchmarkBase {
  kind: "matrix";
  comparison: { label: Role; allowed: number; denied: number; matches: number }[];
  cells: {
    role: Role;
    action: string;
    description: string;
    sql: string;
    expected: string;
    outcome: "allowed" | "denied";
    error: number | null;
    rows: number | null;
    match: boolean;
    why: string;
    elapsed_ms: number;
  }[];
}

export interface CodesResult extends BenchmarkBase {
  kind: "codes";
  comparison: {
    label: string;
    attempts: number;
    codes: Record<string, number>;
    error_1045: number;
    other: number;
    timing: TimingSummary;
  }[];
}

export interface TimingResult extends BenchmarkBase {
  kind: "timing";
  unit: "ms";
  comparison: (TimingSummary & { label: string; [extra: string]: string | number | null })[];
  series: ({ run: number } & Record<string, number>)[];
}

export type BenchmarkResult = MatrixResult | CodesResult | TimingResult;
