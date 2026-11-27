import { describe, expect, it } from "vitest";

import type { FindingsStatusAttributes } from "@/actions/overview";
import type { ProviderProps } from "@/types/providers";

import {
  aiProviders,
  installedScope,
  isCloudAi,
  isModelVendor,
  narrowScope,
  toAiSecurityOverview,
} from "./overview";

const provider = (id: string, type: string, groups: string[] = []) =>
  ({
    id,
    attributes: { provider: type },
    relationships: {
      provider_groups: { data: groups.map((group) => ({ id: group })) },
    },
  }) as ProviderProps;

const status = (
  counts: Pick<FindingsStatusAttributes, "pass" | "fail" | "muted" | "total"> &
    Partial<Pick<FindingsStatusAttributes, "fail_new">>,
) => ({ fail_new: 0, ...counts }) as FindingsStatusAttributes;

const NO_SEVERITY = {
  critical: 0,
  high: 0,
  medium: 0,
  low: 0,
  informational: 0,
};

describe("aiProviders", () => {
  it("keeps the model vendors and the clouds with AI services", () => {
    expect(
      aiProviders([
        provider("p1", "openai"),
        provider("p2", "aws"),
        provider("p3", "kubernetes"),
      ]).map(({ id }) => id),
    ).toEqual(["p1", "p2"]);
  });
});

describe("narrowScope", () => {
  it("keeps the types that pass the test, or none at all", () => {
    const filters = {
      "filter[provider_type__in]": "openai,aws",
      "filter[provider_id__in]": "p1",
    };
    expect(narrowScope(filters, isCloudAi)).toEqual({
      "filter[provider_type__in]": "aws",
      "filter[provider_id__in]": "p1",
    });
    expect(
      narrowScope({ "filter[provider_type__in]": "aws" }, isModelVendor),
    ).toBeNull();
  });
});

describe("installedScope", () => {
  it("asks only for the provider types the tenant has providers of", () => {
    const filters = {
      "filter[provider_type__in]": "claude,openai,chatgpt,aws",
      "filter[provider_id__in]": "p1,p2",
    };
    expect(
      installedScope(filters, [
        provider("p1", "claude"),
        provider("p2", "aws"),
      ]),
    ).toEqual({
      "filter[provider_type__in]": "claude,aws",
      "filter[provider_id__in]": "p1,p2",
    });
    expect(installedScope(filters, [])).toBeNull();
  });
});

const group = (
  id: string,
  severity: string,
  resources: number,
  newFail: number,
  provider = "openai",
) => ({
  id,
  attributes: {
    check_title: `${id} title`,
    status: "FAIL" as const,
    severity,
    impacted_providers: [provider],
    resources_fail: resources,
    new_fail_count: newFail,
    changed_fail_count: 0,
    fail_count: resources,
    last_seen_at: "2026-11-01T00:00:00Z",
  },
});

describe("toAiSecurityOverview", () => {
  const overview = toAiSecurityOverview({
    providers: [
      provider("p1", "openai"),
      provider("p2", "openai"),
      provider("p3", "claude"),
      provider("p4", "aws"),
    ],
    results: {
      openai: status({ pass: 3, fail: 2, muted: 1, total: 10, fail_new: 1 }),
      claude: status({ pass: 7, fail: 7, muted: 0, total: 14, fail_new: 5 }),
    },
    cloudResults: {
      aws: {
        total_findings: 9,
        failed_findings: 4,
        new_failed_findings: 2,
        severity: { ...NO_SEVERITY, critical: 1, high: 3 },
      },
    },
    scannedTypes: ["openai", "aws"],
    severities: {
      openai: { ...NO_SEVERITY, high: 2 },
      claude: { ...NO_SEVERITY, medium: 7 },
    },
    findingGroups: [
      group("apikey_rotated_regularly", "high", 1, 1),
      group("bedrock_guardrails_configured", "critical", 2, 0, "aws"),
      group("project_hosted_tools_restricted", "high", 5, 0),
    ],
  });

  it("totals the model vendors and the clouds' gen-ai findings", () => {
    expect(overview).toMatchObject({ pass: 3 + 7 + 5, fail: 2 + 7 + 4 });
    expect(overview.severity).toMatchObject({
      critical: 1,
      high: 2 + 3,
      medium: 7,
    });
  });

  it("totals the failures that are new since the previous scan, as the Overview does", () => {
    expect(overview.newFail).toBe(1 + 5 + 2);
  });

  it("counts what is neither pass, fail nor muted as manual", () => {
    expect(overview.manual).toBe(4);
  });

  it("gives each provider its failed findings by severity and the services that fail", () => {
    const [vendors, clouds] = overview.layers.map((layer) => layer.providers);
    expect(
      [vendors[1], clouds[0], clouds[1]].map(({ severity, services }) => ({
        severity,
        services,
      })),
    ).toEqual([
      {
        severity: { ...NO_SEVERITY, high: 2 },
        services: ["apikey", "project"],
      },
      {
        severity: { ...NO_SEVERITY, critical: 1, high: 3 },
        services: ["bedrock"],
      },
      { severity: NO_SEVERITY, services: [] },
    ]);
  });

  it("lists every model vendor and cloud, and says which ones are connected and scanned", () => {
    expect(
      overview.layers.map((layer) =>
        layer.providers.map(
          ({ name, scope, connected, scanned, pass, fail }) => [
            name,
            scope,
            connected,
            scanned,
            pass,
            fail,
          ],
        ),
      ),
    ).toEqual([
      [
        ["Claude", "1 account", true, false, 7, 7],
        ["OpenAI", "2 accounts", true, true, 3, 2],
        ["ChatGPT", "0 accounts", false, false, 0, 0],
      ],
      [
        ["AWS", "1 account", true, true, 5, 4],
        ["Azure", "0 accounts", false, false, 0, 0],
        ["Google Cloud", "0 accounts", false, false, 0, 0],
      ],
    ]);
  });

  it("ranks vendor and cloud risks together by severity, then new failures, as on Findings", () => {
    expect(
      overview.topRisks.map(({ checkId, providerName, affected }) => [
        checkId,
        providerName,
        affected,
      ]),
    ).toEqual([
      ["bedrock_guardrails_configured", "AWS", "2 resources"],
      ["apikey_rotated_regularly", "OpenAI", "1 resource"],
      ["project_hosted_tools_restricted", "OpenAI", "5 resources"],
    ]);
  });
});
