import { describe, expect, it } from "vitest";

import type { LighthousePageSuggestions } from "@/types/lighthouse-context";

import { LIGHTHOUSE_CONTEXT_LIMIT } from "./constants";
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
    ["/alerts", "alerts"],
    ["/services", "services"],
    ["/workloads", "workloads"],
    ["/mutelist", "mutelist"],
    ["/roles", "roles"],
    ["/roles/new", "roles"],
    ["/users", "users"],
    ["/invitations", "invitations"],
    ["/invitations/new", "invitations"],
    ["/integrations", "integrations"],
    ["/integrations/jira", "integrations"],
  ])("should resolve %s as %s", (pathname, expectedPageId) => {
    // Given / When
    const page = resolveLighthousePage(pathname);

    // Then
    expect(page.id).toBe(expectedPageId);
    expectValidSuggestions(page.suggestions);
  });

  it("should create a labeled fallback for other application pages", () => {
    // Given / When
    const page = resolveLighthousePage("/profile");

    // Then
    expect(page.id).toBe("other");
    expect(page.label).toBe("Profile");
    expectValidSuggestions(page.suggestions);
  });

  it("should not match routes that only share a page's prefix", () => {
    for (const pathname of [
      "/roles-preview",
      "/users-report",
      "/invitations-archive",
      "/integrations-beta",
    ]) {
      expect(resolveLighthousePage(pathname).id).toBe("other");
    }
  });

  it("should title-case multi-segment fallback routes", () => {
    const page = resolveLighthousePage("/manage-groups");

    expect(page.id).toBe("other");
    expect(page.label).toBe("Manage Groups");
    expect(page.allowedSearchParams).toEqual([]);
  });

  it("should resolve encoded and decoded dynamic paths to the same scope", () => {
    expect(getLighthouseScopeKey("/compliance/CSA%20CCM")).toBe(
      getLighthouseScopeKey("/compliance/CSA CCM"),
    );
  });

  it("should keep dynamic route scope keys inside the context schema limit", () => {
    // Given
    const pathname = `/compliance/${"a".repeat(300)}`;

    // When
    const context = buildLighthousePageContext(pathname, new URLSearchParams());

    // Then
    expect(context.scopeKey).toBe(getLighthouseScopeKey(pathname));
    expect(context.scopeKey.length).toBeLessThanOrEqual(
      LIGHTHOUSE_CONTEXT_LIMIT.STRING_LENGTH,
    );
  });
});

function expectValidSuggestions(suggestions: LighthousePageSuggestions) {
  expect(suggestions).toHaveLength(4);
  expect(new Set(suggestions.map(({ prompt }) => prompt)).size).toBe(
    suggestions.length,
  );

  for (const suggestion of suggestions) {
    expect(suggestion).toEqual(
      expect.objectContaining({
        label: expect.any(String),
        prompt: expect.any(String),
      }),
    );
    expect(suggestion.label.trim()).not.toBe("");
    expect(suggestion.prompt.trim()).not.toBe("");
  }
}

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

  it("should preserve the filter names emitted by the alerts page", () => {
    const context = buildLighthousePageContext(
      "/alerts",
      new URLSearchParams({
        "filter[enabled]": "true",
        "filter[trigger]": "new_failing_findings",
        "filter[search]": "s3",
        edit: "alert-1",
      }),
    );

    expect(context.filters).toEqual({
      enabled: ["true"],
      search: ["s3"],
      trigger: ["new_failing_findings"],
    });
  });

  it("should preserve the filter names emitted by tenant admin pages", () => {
    const roles = buildLighthousePageContext(
      "/roles",
      new URLSearchParams({
        "filter[search]": "admin",
        sort: "name",
        "filter[permission_state]": "unlimited",
      }),
    );
    const users = buildLighthousePageContext(
      "/users",
      new URLSearchParams({ "filter[search]": "alice" }),
    );
    const invitations = buildLighthousePageContext(
      "/invitations",
      new URLSearchParams({ "filter[state]": "expired" }),
    );

    expect(roles.filters).toEqual({
      permission_state: ["unlimited"],
      search: ["admin"],
      sort: ["name"],
    });
    expect(users.filters).toEqual({ search: ["alice"] });
    expect(invitations.filters).toEqual({ state: ["expired"] });
  });

  it("should capture only sort on integrations pages", () => {
    // The integration sub-pages pin filter[integration_type] server-side; the
    // open integration reaches Lighthouse through the page item's path.
    const context = buildLighthousePageContext(
      "/integrations/jira",
      new URLSearchParams({
        sort: "-inserted_at",
        "filter[integration_type]": "jira",
      }),
    );

    expect(context.path).toBe("/integrations/jira");
    expect(context.filters).toEqual({ sort: ["-inserted_at"] });
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

  it("should discard sensitive values from allowed search parameters", () => {
    // Given
    const searchParams = new URLSearchParams();
    searchParams.append("filter[search]", "security@example.com");
    searchParams.append("filter[search]", "10.0.0.1");
    searchParams.append("filter[search]", "2001:db8::1");
    searchParams.append("filter[search]", "Bearer sensitive-value");
    searchParams.append("filter[search]", "arn:aws:s3:::example");
    searchParams.append("filter[search]", "12:30:00");
    searchParams.append("filter[search]", "public bucket");

    // When
    const context = buildLighthousePageContext("/findings", searchParams);

    // Then
    expect(context.filters).toEqual({
      search: ["arn:aws:s3:::example", "12:30:00", "public bucket"],
    });
  });
});
