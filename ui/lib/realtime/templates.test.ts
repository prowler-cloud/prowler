import { readFileSync } from "node:fs";
import { resolve } from "node:path";

import { describe, expect, it } from "vitest";

import {
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
        resolve(__dirname, "../../../permissions/templates", file),
        "utf8",
      ),
    )
    .join("\n");

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
      expect(template.content).toMatch(/sts:ExternalId/);
    }
  });
});
