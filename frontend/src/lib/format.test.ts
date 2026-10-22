import { describe, expect, it } from "vitest";
import type { QueryResult } from "../types";
import { cellText, clampRuns, describeExpectation, describeOutcome, formatMs, matchesExpectation } from "./format";

const base = { role: "student", account: "alice_student@%", active_role: "student_role", elapsed_ms: 0.4 } as const;
const allowed: QueryResult = { ...base, ok: true, kind: "read", outcome: "allowed", columns: ["code"], rows: [["CS201"]], row_count: 1 };
const write: QueryResult = { ...base, ok: true, kind: "write", outcome: "allowed", columns: [], rows: [], affected_rows: 1, rolled_back: true };
const denied: QueryResult = {
  ...base,
  ok: false,
  kind: "read",
  outcome: "denied",
  error: { code: 1142, message: "SELECT command denied", outcome: "denied", hint: "the command is denied for this table" },
};

describe("formatMs", () => {
  it("chooses precision by size", () => {
    expect(formatMs(0.3337)).toBe("0.334 ms");
    expect(formatMs(4.871)).toBe("4.87 ms");
    expect(formatMs(1234.4)).toBe("1234 ms");
    expect(formatMs(undefined)).toBe("-");
    expect(formatMs(Number.NaN)).toBe("-");
  });
});

describe("describeOutcome", () => {
  it("describes reads, writes and refusals", () => {
    expect(describeOutcome(allowed)).toBe("allowed: 1 row");
    expect(describeOutcome({ ...allowed, row_count: 200, truncated: true })).toBe("allowed: 200 rows (truncated)");
    expect(describeOutcome(write)).toBe("allowed: 1 row affected, rolled back");
    expect(describeOutcome(denied)).toBe("denied (error 1142)");
    expect(describeOutcome({ ...denied, outcome: "error", error: { ...denied.error!, code: 1146 } })).toBe("error (error 1146)");
  });
});

describe("matchesExpectation", () => {
  it("compares outcome, row count and error code", () => {
    expect(matchesExpectation({ outcome: "allowed", rows: 1 }, allowed)).toBe(true);
    expect(matchesExpectation({ outcome: "allowed", rows: 4 }, allowed)).toBe(false);
    expect(matchesExpectation({ outcome: "allowed", rows: 1 }, write)).toBe(true);
    expect(matchesExpectation({ outcome: "denied", error: 1142 }, denied)).toBe(true);
    expect(matchesExpectation({ outcome: "denied", error: 1143 }, denied)).toBe(false);
    expect(matchesExpectation({ outcome: "allowed", rows: 1 }, denied)).toBe(false);
  });
  it("words expectations like the results", () => {
    expect(describeExpectation({ outcome: "allowed", rows: 1 })).toBe("allowed: 1 row");
    expect(describeExpectation({ outcome: "denied", error: 1142 })).toBe("denied (error 1142)");
  });
});

describe("small helpers", () => {
  it("shows NULL and clamps runs", () => {
    expect(cellText(null)).toBe("NULL");
    expect(cellText(false)).toBe("false");
    expect(clampRuns(1)).toBe(5);
    expect(clampRuns(1000)).toBe(200);
    expect(clampRuns(Number.NaN)).toBe(5);
    expect(clampRuns(30.4)).toBe(30);
  });
});
