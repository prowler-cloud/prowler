import { readFileSync } from "node:fs";
import { resolve } from "node:path";

import { describe, expect, it } from "vitest";

import {
  COST_CLOUDFORMATION,
  COST_TERRAFORM,
  FEED_CLOUDFORMATION,
  FEED_TERRAFORM,
  REMEDIATION_CLOUDFORMATION,
  REMEDIATION_TERRAFORM,
} from "./templates";

const repoFile = (path: string) =>
  path
    .split("+")
    .map((file) =>
      readFileSync(
        resolve(__dirname, "../../../../../permissions/templates", file),
        "utf8",
      ),
    )
    .join("\n");

// Values of a policy field in CloudFormation (`Key: v`) or Terraform (`Key = ["v"]`).
const policyField = (content: string, field: string) =>
  Array.from(
    content.matchAll(
      new RegExp(`\\b${field}\\s*[:=]\\s*(\\[[^\\]]*\\]|\\S+)`, "g"),
    ),
    ([, value]) => value.replace(/[[\]"\s]/g, "").split(","),
  ).flat();

const terraformModule = (name: string) =>
  ["main", "variables", "outputs"]
    .map((file) => `terraform/${name}/${file}.tf`)
    .join("+");

describe("embedded Prowler Realtime templates", () => {
  it.each([
    [
      REMEDIATION_CLOUDFORMATION,
      "cloudformation/prowler-realtime-remediation-role.yml",
    ],
    [REMEDIATION_TERRAFORM, terraformModule("realtime-remediation-role")],
    [FEED_CLOUDFORMATION, "cloudformation/prowler-realtime-feed.yml"],
    [FEED_TERRAFORM, terraformModule("realtime-feed")],
    [COST_CLOUDFORMATION, "cloudformation/prowler-realtime-cost.yml"],
    [COST_TERRAFORM, terraformModule("realtime-cost")],
  ])("%s matches the file in permissions/templates", (template, path) => {
    expect(template.content).toBe(repoFile(path));
  });

  it("never grants more than the fixes need, and always requires the external id", () => {
    for (const template of [
      REMEDIATION_CLOUDFORMATION,
      REMEDIATION_TERRAFORM,
    ]) {
      expect(template.content).not.toMatch(
        /Action:\s*['"]?\*|actions\s*=\s*\["\*"\]/,
      );
      // No service-wide wildcard either, such as ec2:*.
      expect(template.content).not.toMatch(
        /(?:Action:|actions\s*=)[^\n]*\b[a-z0-9-]+:\*/,
      );
      expect(template.content).toMatch(/sts:ExternalId/);
    }
  });

  it.each([
    [COST_CLOUDFORMATION, /RoleName: !Ref ProwlerScanRoleName\n/],
    [COST_TERRAFORM, /role = var\.prowler_scan_role_name\n/],
  ])(
    "%s lets the scan role read Cost Explorer and nothing else",
    (template, scanRole) => {
      expect(policyField(template.content, "Effect")).toEqual(["Allow"]);
      expect(policyField(template.content, "Action")).toEqual([
        "ce:GetCostAndUsage",
      ]);
      expect(policyField(template.content, "Resource")).toEqual(["*"]);
      expect(template.content).not.toMatch(/NotAction|NotResource/);
      expect(template.content).toMatch(scanRole);
    },
  );
});
