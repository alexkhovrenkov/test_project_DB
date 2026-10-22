// The only place that talks to the backend (app/lab_server.py). No credentials ever reach the browser.
import type { BenchmarkResult, ExamplesResponse, Health, QueryResult, Role, Scenario, Stats } from "./types";

export class ApiError extends Error {
  constructor(
    message: string,
    readonly status: number,
    readonly databaseDown = false,
  ) {
    super(message);
    this.name = "ApiError";
  }
}

/** Turn an HTTP response (or a failed fetch) into data or one ApiError with a readable message. */
export async function parseResponse<T>(response: Response): Promise<T> {
  let body: unknown = null;
  try {
    body = await response.json();
  } catch {
    // not JSON: handled below
  }
  if (!response.ok) {
    const message =
      body && typeof body === "object" && "error" in body && typeof body.error === "string"
        ? body.error
        : `The lab backend answered HTTP ${response.status}.`;
    throw new ApiError(message, response.status, response.status === 503);
  }
  if (body === null) throw new ApiError("The lab backend sent an empty or invalid answer.", response.status);
  return body as T;
}

async function request<T>(path: string, init: RequestInit = {}, timeoutMs = 20000): Promise<T> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const response = await fetch(path, { ...init, signal: controller.signal });
    return await parseResponse<T>(response);
  } catch (error) {
    if (error instanceof ApiError) throw error;
    if (error instanceof DOMException && error.name === "AbortError") {
      throw new ApiError(`No answer from the lab backend within ${timeoutMs / 1000} s.`, 0);
    }
    throw new ApiError("Cannot reach the lab backend. Is it running? Start it with: make lab", 0, true);
  } finally {
    clearTimeout(timer);
  }
}

const post = (body: unknown): RequestInit => ({
  method: "POST",
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify(body),
});

export const api = {
  health: () => request<Health>("/api/health", {}, 8000),
  examples: () => request<ExamplesResponse>("/api/examples"),
  stats: () => request<Stats>("/api/stats"),
  scenarios: () => request<{ scenarios: Scenario[] }>("/api/scenarios"),
  query: (role: Role, sql: string) => request<QueryResult>("/api/query", post({ role, sql })),
  benchmark: (scenario: string, runs: number) =>
    request<BenchmarkResult>("/api/benchmark", post({ scenario, runs }), 120000),
};
