import { describe, expect, it } from "vitest";

import {
  actionStatusBadge,
  anomalyHref,
  frameworkLabel,
  isDriftDetection,
  isLighthouseAction,
  parseAnomalyId,
  ROUTE_LEGEND,
  settingsHref,
  detectionStatusBadge,
  failureCopy,
  formatRelativeTime,
  humanize,
  orderedSeverities,
  policyChangesAccount,
  routeBadge,
  safeExternalUrl,
} from "./display";

describe("realtime display helpers", () => {
  it("maps route values to the three labelled badges", () => {
    expect(routeBadge("auto")).toEqual({ label: "Auto-fix", tone: "success" });
    expect(routeBadge("pr").label).toBe("Pull request");
    expect(routeBadge("manual").tone).toBe("warning");
  });

  it("labels findings outside the enforced frameworks", () => {
    expect(routeBadge("not_enforced")).toEqual({
      label: "Not enforced",
      tone: "outline",
    });
    expect(Object.keys(ROUTE_LEGEND).sort()).toEqual(
      ["auto", "manual", "not_enforced", "pr"].sort(),
    );
  });

  it("recognises compliance drift and Lighthouse AI actions", () => {
    expect(isDriftDetection({ rule_id: "framework_drift" })).toBe(true);
    expect(isDriftDetection({ rule_id: "s3_public_acl" })).toBe(false);
    expect(isLighthouseAction({ summary: "Lighthouse AI fix for rds_x" })).toBe(
      true,
    );
    expect(
      isLighthouseAction({ summary: "Lighthouse AI proposal rejected: gate" }),
    ).toBe(true);
    expect(isLighthouseAction({ summary: "Enabled public access block" })).toBe(
      false,
    );
  });

  it("names a framework from the catalog and falls back to its id", () => {
    const catalog = [{ id: "soc2_aws", name: "SOC 2" }];
    expect(frameworkLabel("soc2_aws", catalog)).toBe("SOC 2");
    expect(frameworkLabel("pci_aws", catalog)).toBe("pci_aws");
    expect(frameworkLabel("soc2_aws")).toBe("soc2_aws");
  });

  it("builds and parses anomaly routes", () => {
    const id = "Amazon Elastic Compute Cloud - Compute|eu-west-1";
    expect(parseAnomalyId(id)).toEqual({
      service: "Amazon Elastic Compute Cloud - Compute",
      region: "eu-west-1",
    });
    expect(parseAnomalyId("nopipe")).toBeNull();
    expect(parseAnomalyId("|region")).toBeNull();
    expect(parseAnomalyId("service|")).toBeNull();
    expect(anomalyHref("EC2|eu-west-1", "p1")).toBe(
      "/realtime/cost-anomalies/EC2%7Ceu-west-1?provider=p1",
    );
    expect(settingsHref("p1")).toBe("/realtime/settings?provider=p1");
    expect(settingsHref(undefined)).toBe("/realtime/settings");
    expect(settingsHref("p1", "/realtime/settings/cost-anomalies")).toBe(
      "/realtime/settings/cost-anomalies?provider=p1",
    );
  });

  it("tones action statuses and falls back for unknown ones", () => {
    expect(actionStatusBadge("fixed_verified").tone).toBe("success");
    expect(actionStatusBadge("fix_failed").tone).toBe("error");
    expect(actionStatusBadge("pr_blocked").tone).toBe("error");
    expect(actionStatusBadge("something_new")).toEqual({
      label: "Something new",
      tone: "tag",
    });
  });

  it("names detection verdicts", () => {
    expect(detectionStatusBadge("violation").tone).toBe("error");
    expect(detectionStatusBadge("compliant").tone).toBe("success");
    expect(detectionStatusBadge("out_of_scope").label).toBe("Out of scope");
  });

  it("only a live auto policy changes the account", () => {
    const base = { enabled: true, mode: "auto", dry_run: false };
    expect(policyChangesAccount(base)).toBe(true);
    expect(policyChangesAccount({ ...base, dry_run: true })).toBe(false);
    expect(policyChangesAccount({ ...base, mode: "pr" })).toBe(false);
    expect(policyChangesAccount({ ...base, enabled: false })).toBe(false);
  });

  it("orders severities worst first and skips zeroes", () => {
    expect(
      orderedSeverities({ low: 1, critical: 2, medium: 0, high: 3 }),
    ).toEqual([
      ["critical", 2],
      ["high", 3],
      ["low", 1],
    ]);
  });

  it("formats relative times", () => {
    const now = Date.parse("2026-10-23T12:00:00Z");
    expect(formatRelativeTime("2026-10-23T11:59:50Z", now)).toBe("just now");
    expect(formatRelativeTime("2026-10-23T11:50:00Z", now)).toBe("10 min ago");
    expect(formatRelativeTime("2026-10-23T09:00:00Z", now)).toBe("3 h ago");
    expect(formatRelativeTime(null, now)).toBe("never");
  });

  it("only links http(s) URLs", () => {
    expect(safeExternalUrl("https://github.com/a/b/pull/1")).toContain(
      "github.com",
    );
    expect(safeExternalUrl("javascript:alert(1)")).toBeNull();
    expect(safeExternalUrl("not a url")).toBeNull();
  });

  it("explains a 503 as a missing data store and a 403 as no access", () => {
    expect(failureCopy(503).title).toMatch(/data store not configured/i);
    expect(failureCopy(403).title).toMatch(/do not have access/i);
    expect(failureCopy(404).title).toMatch(/not available/i);
  });

  it("humanizes snake case", () => {
    expect(humanize("access_denied_burst")).toBe("Access denied burst");
  });
});
