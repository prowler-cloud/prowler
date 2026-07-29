import { describe, expect, it } from "vitest";

import { isOnFlowRoute } from "../flow-route";

const query = (search: string) => new URLSearchParams(search);

describe("isOnFlowRoute", () => {
  it("matches a plain route on the same pathname", () => {
    expect(isOnFlowRoute("/findings", "/findings", query(""))).toBe(true);
  });

  it("ignores extra params the user built up", () => {
    expect(
      isOnFlowRoute(
        "/compliance?tab=per-scan",
        "/compliance",
        query("tab=per-scan&scanId=scan-1&filter%5Bregion__in%5D=eu-west-1"),
      ),
    ).toBe(true);
  });

  it("rejects a different pathname", () => {
    expect(
      isOnFlowRoute("/compliance?tab=per-scan", "/findings", query("")),
    ).toBe(false);
  });

  it("rejects the same pathname when a pinned param is missing", () => {
    expect(
      isOnFlowRoute("/compliance?tab=per-scan", "/compliance", query("")),
    ).toBe(false);
  });

  it("rejects the same pathname when a pinned param has another value", () => {
    expect(
      isOnFlowRoute("/scans?tab=active", "/scans", query("tab=scheduled")),
    ).toBe(false);
  });

  it("requires every pinned param, not just the first", () => {
    expect(
      isOnFlowRoute(
        "/scans?tab=active&view=list",
        "/scans",
        query("tab=active"),
      ),
    ).toBe(false);
  });
});
