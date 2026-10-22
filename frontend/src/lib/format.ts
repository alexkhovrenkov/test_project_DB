// Pure helpers for showing MariaDB's answers. Kept free of React so they can be unit-tested.
import type { Expectation, QueryResult } from "../types";

export function formatMs(value: number | null | undefined): string {
  if (value === null || value === undefined || Number.isNaN(value)) return "-";
  if (value < 1) return `${value.toFixed(3)} ms`;
  if (value < 100) return `${value.toFixed(2)} ms`;
  return `${Math.round(value)} ms`;
}

/** "allowed (4 rows)", "denied (error 1142)", "1 row affected (rolled back)" ... */
export function describeOutcome(result: QueryResult): string {
  if (!result.ok) {
    const code = result.error?.code;
    return `${result.outcome === "denied" ? "denied" : "error"}${code ? ` (error ${code})` : ""}`;
  }
  if (result.kind === "write") {
    const count = result.affected_rows ?? 0;
    return `allowed: ${count} ${count === 1 ? "row" : "rows"} affected${result.rolled_back ? ", rolled back" : ""}`;
  }
  const count = result.row_count ?? 0;
  return `allowed: ${count} ${count === 1 ? "row" : "rows"}${result.truncated ? " (truncated)" : ""}`;
}

export function describeExpectation(expect: Expectation): string {
  if (expect.outcome === "allowed") {
    return expect.rows === undefined ? "allowed" : `allowed: ${expect.rows} ${expect.rows === 1 ? "row" : "rows"}`;
  }
  return `${expect.outcome}${expect.error ? ` (error ${expect.error})` : ""}`;
}

/** Does MariaDB's actual answer match what the example documents? */
export function matchesExpectation(expect: Expectation, result: QueryResult): boolean {
  if (expect.outcome !== result.outcome) return false;
  if (expect.outcome === "allowed") {
    const count = result.kind === "write" ? result.affected_rows : result.row_count;
    return expect.rows === undefined || expect.rows === count;
  }
  return expect.error === undefined || expect.error === result.error?.code;
}

export function cellText(value: string | number | boolean | null): string {
  if (value === null) return "NULL";
  return String(value);
}

export function clampRuns(value: number, low = 5, high = 200): number {
  if (!Number.isFinite(value)) return low;
  return Math.min(high, Math.max(low, Math.round(value)));
}
