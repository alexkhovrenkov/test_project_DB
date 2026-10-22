import { describe, expect, it } from "vitest";
import { hrefFor, pageFromHash } from "./router";

describe("hash router", () => {
  it("maps hashes to pages and falls back to home", () => {
    expect(pageFromHash("#/playground")).toBe("playground");
    expect(pageFromHash("#/docs?s=schema")).toBe("docs");
    expect(pageFromHash("#/analytics/x")).toBe("analytics");
    expect(pageFromHash("")).toBe("home");
    expect(pageFromHash("#/admin")).toBe("home");
    expect(hrefFor("home")).toBe("#/");
    expect(hrefFor("docs")).toBe("#/docs");
  });
});
