import { Ban, CircleCheck, Clock, KeyRound, Rows3, ShieldCheck, TriangleAlert, Undo2 } from "lucide-react";
import { cellText, describeExpectation, describeOutcome, formatMs, matchesExpectation } from "../lib/format";
import type { Expectation, QueryResult } from "../types";
import { Badge } from "./ui";

export function OutcomeBadge({ result }: { result: QueryResult }) {
  if (result.outcome === "allowed")
    return (
      <Badge tone="green">
        <CircleCheck size={13} aria-hidden /> Allowed by MariaDB
      </Badge>
    );
  if (result.outcome === "denied")
    return (
      <Badge tone="red">
        <Ban size={13} aria-hidden /> Denied by MariaDB
      </Badge>
    );
  return (
    <Badge tone="amber">
      <TriangleAlert size={13} aria-hidden /> MariaDB error
    </Badge>
  );
}

export function ResultPanel({ result, expect }: { result: QueryResult; expect?: Expectation }) {
  const matched = expect ? matchesExpectation(expect, result) : null;
  return (
    <div className="space-y-3">
      <div className="flex flex-wrap items-center gap-2 text-xs text-slate-600">
        <OutcomeBadge result={result} />
        <span className="inline-flex items-center gap-1">
          <Clock size={13} aria-hidden /> {formatMs(result.elapsed_ms)}
          <span className="text-slate-400">(measured by the backend)</span>
        </span>
        <span className="inline-flex items-center gap-1">
          <Rows3 size={13} aria-hidden /> {describeOutcome(result)}
        </span>
        <span className="inline-flex items-center gap-1">
          <KeyRound size={13} aria-hidden /> {result.account}
          {result.active_role && <span className="text-slate-400">· {result.active_role}</span>}
        </span>
        <span className="inline-flex items-center gap-1">
          <ShieldCheck size={13} aria-hidden /> TLS verified, ED25519
        </span>
        {result.rolled_back && (
          <span className="inline-flex items-center gap-1">
            <Undo2 size={13} aria-hidden /> rolled back
          </span>
        )}
      </div>

      {expect && (
        <p className={`text-xs ${matched ? "text-emerald-700" : "text-amber-800"}`}>
          Documented: <strong>{describeExpectation(expect)}</strong> · Observed: <strong>{describeOutcome(result)}</strong>{" "}
          {matched ? "- matches." : "- differs (you edited the SQL or role, or the server behaves differently)."}
        </p>
      )}

      {!result.ok && result.error && (
        <div
          className={`rounded-lg border px-3.5 py-3 font-mono text-[13px] ${
            result.outcome === "denied" ? "border-red-200 bg-red-50 text-red-900" : "border-amber-200 bg-amber-50 text-amber-900"
          }`}
        >
          <p>
            ERROR {result.error.code}: {result.error.message}
          </p>
          {result.error.hint && <p className="mt-1 font-sans text-xs opacity-80">Meaning: {result.error.hint}.</p>}
        </div>
      )}

      {result.ok && result.columns && result.columns.length > 0 && (
        <div className="max-h-80 overflow-auto rounded-lg border border-slate-200">
          <table className="min-w-full text-left text-[13px]">
            <thead className="sticky top-0 bg-slate-50 text-xs uppercase tracking-wide text-slate-500">
              <tr>
                {result.columns.map((column, index) => (
                  <th key={index} className="whitespace-nowrap border-b border-slate-200 px-3 py-2 font-semibold">
                    {column}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody className="font-mono">
              {result.rows?.map((row, rowIndex) => (
                <tr key={rowIndex} className="odd:bg-white even:bg-slate-50/60">
                  {row.map((value, index) => (
                    <td key={index} className={`whitespace-nowrap px-3 py-1.5 ${value === null ? "text-slate-400" : "text-slate-800"}`}>
                      {cellText(value)}
                    </td>
                  ))}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      {result.ok && result.columns && result.columns.length > 0 && result.rows?.length === 0 && (
        <p className="text-sm text-slate-500">MariaDB returned no rows (the statement was allowed).</p>
      )}
      {result.ok && result.kind === "write" && (
        <p className="text-sm text-slate-600">
          MariaDB accepted the write and reported {result.affected_rows ?? 0} affected row(s). The lab rolled the transaction
          back, so the data is unchanged.
        </p>
      )}
    </div>
  );
}
