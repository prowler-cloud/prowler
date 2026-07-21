import { describe, expect, it } from "vitest";

import {
  buildLighthousePageContext,
  getLighthouseScopeKey,
  resolveLighthousePage,
} from "./pages";

describe("resolveLighthousePage", () => {
  it.each([
    ["/", "overview"],
    ["/findings", "findings"],
    ["/resources", "resources"],
    ["/compliance", "compliance"],
    ["/compliance/cis-1.5-aws", "compliance-detail"],
    ["/attack-paths/query-builder", "attack-paths"],
    ["/scans", "scans"],
    ["/providers", "providers"],
  ])("should resolve %s as %s", (pathname, expectedPageId) => {
    // Given / When
    const page = resolveLighthousePage(pathname);

    // Then
    expect(page.id).toBe(expectedPageId);
    expect(page.suggestions).toHaveLength(4);
  });

  it("should create a labeled fallback for other application pages", () => {
    // Given / When
    const page = resolveLighthousePage("/alerts/");

    // Then
    expect(page.id).toBe("other");
    expect(page.label).toBe("Alerts");
    expect(page.suggestions).toHaveLength(4);
  });

  it("should resolve encoded and decoded dynamic paths to the same scope", () => {
    expect(getLighthouseScopeKey("/compliance/CSA%20CCM")).toBe(
      getLighthouseScopeKey("/compliance/CSA CCM"),
    );
  });
});

describe("buildLighthousePageContext", () => {
  it("should include only declared search parameters with semantic filter keys", () => {
    // Given
    const searchParams = new URLSearchParams();
    searchParams.append("filter[severity__in]", "critical,high");
    searchParams.append("filter[status__in]", "FAIL");
    searchParams.append("sort", "-severity");
    searchParams.append("email", "security@example.com");
    searchParams.append("filter[unknown_future_key]", "secret");

    // When
    const context = buildLighthousePageContext("/findings/", searchParams);

    // Then
    expect(context).toEqual({
      kind: "page",
      id: "findings",
      source: "automatic",
      scopeKey: "findings:/findings",
      label: "Findings",
      path: "/findings",
      filters: {
        severity: ["critical", "high"],
        sort: ["-severity"],
        status: ["FAIL"],
      },
    });
  });

  it("should preserve whitelisted compliance detail identifiers", () => {
    const context = buildLighthousePageContext(
      "/compliance/cis-aws",
      new URLSearchParams({
        complianceId: "cis_aws_1.5",
        version: "1.5",
        scanId: "scan-1",
        mode: "per-scan",
        "filter[cis_profile_level]": "Level 1",
      }),
    );

    expect(context.filters).toEqual({
      cis_profile_level: ["Level 1"],
      complianceId: ["cis_aws_1.5"],
      mode: ["per-scan"],
      scanId: ["scan-1"],
      version: ["1.5"],
    });
  });

  it("should preserve the selected scan identifier on the scans page", () => {
    const context = buildLighthousePageContext(
      "/scans",
      new URLSearchParams({ scanId: "scan-1", tab: "completed" }),
    );

    expect(context.filters).toEqual({
      scanId: ["scan-1"],
      tab: ["completed"],
    });
  });

  it("should preserve the filter names emitted by list-page controls", () => {
    const findings = buildLighthousePageContext(
      "/findings",
      new URLSearchParams({
        "filter[search]": "public bucket",
        "filter[scan__in]": "scan-1",
        "filter[inserted_at]": "2026-07-01,2026-07-21",
      }),
    );
    const providers = buildLighthousePageContext(
      "/providers",
      new URLSearchParams({ "filter[connected]": "true" }),
    );

    expect(findings.filters).toEqual({
      inserted_at: ["2026-07-01", "2026-07-21"],
      scan: ["scan-1"],
      search: ["public bucket"],
    });
    expect(providers.filters).toEqual({ connected: ["true"] });
  });
});
