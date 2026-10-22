import { describe, expect, it } from "vitest";
import { ApiError, parseResponse } from "./api";

const json = (status: number, body: unknown) =>
  new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } });

describe("parseResponse", () => {
  it("returns the data of a successful answer", async () => {
    await expect(parseResponse(json(200, { database: "up" }))).resolves.toEqual({ database: "up" });
  });
  it("uses the backend's error message", async () => {
    await expect(parseResponse(json(400, { error: "Run one statement at a time" }))).rejects.toThrow("Run one statement at a time");
  });
  it("marks 503 as database down", async () => {
    const error: ApiError = await parseResponse<never>(json(503, { error: "MariaDB is not answering", database: "down" })).catch((e: unknown) => e as ApiError);
    expect(error).toBeInstanceOf(ApiError);
    expect(error.databaseDown).toBe(true);
    expect(error.status).toBe(503);
  });
  it("handles answers that are not JSON", async () => {
    await expect(parseResponse(new Response("Bad gateway", { status: 502 }))).rejects.toThrow("HTTP 502");
    await expect(parseResponse(new Response("", { status: 200 }))).rejects.toThrow("empty or invalid");
  });
});
