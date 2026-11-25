import { describe, expect, it } from "vitest";

import type { FindingsStatusAttributes } from "@/actions/overview";
import type { ProviderProps } from "@/types/providers";

import {
  aiProvidersInScope,
  aiScopeFilters,
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
  counts: Pick<FindingsStatusAttributes, "pass" | "fail" | "muted" | "total">,
) => counts as FindingsStatusAttributes;

const NO_SEVERITY = {
  critical: 0,
  high: 0,
  medium: 0,
  low: 0,
  informational: 0,
};

describe("aiScopeFilters", () => {
  it("keeps only the AI-SPM provider types the page selects", () => {
    expect(
      aiScopeFilters({
        "filter[provider_type__in]": "aws,kubernetes,openai",
        "filter[provider_id__in]": "p1",
      }),
    ).toEqual({
      "filter[provider_type__in]": "openai,aws",
      "filter[provider_id__in]": "p1",
    });
  });

  it("has no scope when the selection leaves out every AI-SPM provider", () => {
    expect(
      aiScopeFilters({ "filter[provider_type__in]": "kubernetes" }),
    ).toBeNull();
  });
});

describe("aiProvidersInScope", () => {
  it("keeps every AI-SPM provider type the account filter allows", () => {
    expect(
      aiProvidersInScope(
        [
          provider("p1", "openai"),
          provider("p2", "claude"),
          provider("p3", "aws"),
          provider("p4", "openai"),
          provider("p5", "kubernetes"),
        ],
        {
          "filter[provider_type__in]": "openai",
          "filter[provider_id__in]": "p1,p2,p3,p5",
        },
      ).map(({ id }) => id),
    ).toEqual(["p1", "p2", "p3"]);
  });

  it("keeps only the providers in the selected groups", () => {
    expect(
      aiProvidersInScope(
        [provider("p1", "claude", ["g1"]), provider("p2", "aws", ["g2"])],
        {
          "filter[provider_type__in]": "claude,aws",
          "filter[provider_groups__in]": "g2",
        },
      ).map(({ id }) => id),
    ).toEqual(["p2"]);
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
    types: ["openai", "aws"],
    results: {
      openai: status({ pass: 3, fail: 2, muted: 1, total: 10 }),
      claude: status({ pass: 7, fail: 7, muted: 0, total: 14 }),
    },
    cloudResults: {
      aws: {
        total_findings: 9,
        failed_findings: 4,
        new_failed_findings: 0,
        severity: { ...NO_SEVERITY, critical: 1, high: 3 },
      },
    },
    scannedTypes: ["openai", "aws"],
    severity: { ...NO_SEVERITY, high: 2 },
    findingGroups: [
      group("apikey_rotated_regularly", "high", 1, 1),
      group("bedrock_guardrails_configured", "critical", 2, 0, "aws"),
      group("project_hosted_tools_restricted", "high", 5, 0),
    ],
  });

  it("totals the model vendors and the clouds' gen-ai findings the page is filtered to", () => {
    expect(overview).toMatchObject({ pass: 3 + 5, fail: 2 + 4 });
    expect(overview.severity).toMatchObject({ critical: 1, high: 2 + 3 });
  });

  it("counts what is neither pass, fail nor muted as manual", () => {
    expect(overview.manual).toBe(4);
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
