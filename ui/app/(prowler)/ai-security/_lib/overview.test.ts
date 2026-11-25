import { describe, expect, it } from "vitest";

import type { FindingsStatusAttributes } from "@/actions/overview";
import type {
  AttributesItemData,
  RequirementItemData,
} from "@/types/compliance";
import type { ProviderProps } from "@/types/providers";

import { aiScopeFilters, parseSection, toAiSecurityOverview } from "./overview";

const provider = (id: string, type: string) =>
  ({ id, attributes: { provider: type } }) as ProviderProps;

const status = (
  counts: Pick<FindingsStatusAttributes, "pass" | "fail" | "muted" | "total">,
) => counts as FindingsStatusAttributes;

const requirement = (id: string, status: string) =>
  ({ id, attributes: { status } }) as RequirementItemData;

const attribute = (id: string, Section: string) =>
  ({
    id,
    attributes: { attributes: { metadata: [{ Section }] } },
  }) as never as AttributesItemData;

const NO_SEVERITY = {
  critical: 0,
  high: 0,
  medium: 0,
  low: 0,
  informational: 0,
};

describe("aiScopeFilters", () => {
  it("keeps only the AI provider types the page selects", () => {
    expect(
      aiScopeFilters({
        "filter[provider_type__in]": "aws,openai",
        "filter[provider_id__in]": "p1",
      }),
    ).toEqual({
      "filter[provider_type__in]": "openai",
      "filter[provider_id__in]": "p1",
    });
  });

  it("has no scope when the selection leaves out every AI provider", () => {
    expect(aiScopeFilters({ "filter[provider_type__in]": "aws" })).toBeNull();
  });
});

describe("parseSection", () => {
  it("splits a numbered code from the section name", () => {
    expect(parseSection("LLM01:2025 Prompt Injection")).toEqual({
      code: "LLM01",
      name: "Prompt Injection",
    });
    expect(parseSection("GOVERN")).toEqual({ code: "", name: "GOVERN" });
  });
});

describe("toAiSecurityOverview", () => {
  const overview = toAiSecurityOverview({
    providers: [provider("p1", "openai"), provider("p2", "openai")],
    results: {
      openai: status({ pass: 3, fail: 2, muted: 1, total: 10 }),
    },
    severity: { ...NO_SEVERITY, high: 2 },
    frameworks: [
      {
        overview: {
          id: "owasp_llm_top_10_2025",
          type: "compliance-overviews",
          attributes: {
            framework: "OWASP-LLM-Top-10",
            version: "2025",
            requirements_passed: 1,
            requirements_failed: 1,
            requirements_manual: 1,
            total_requirements: 3,
          },
        },
        requirements: [
          requirement("LLM01.1", "PASS"),
          requirement("LLM01.2", "FAIL"),
          requirement("LLM02.1", "MANUAL"),
        ],
        attributes: [
          attribute("LLM01.1", "LLM01:2025 Prompt Injection"),
          attribute("LLM01.2", "LLM01:2025 Prompt Injection"),
          attribute("LLM02.1", "LLM02:2025 Sensitive Information Disclosure"),
        ],
      },
    ],
    findingGroups: [
      {
        id: "apikey_rotated_regularly",
        attributes: {
          check_title: "API keys are rotated",
          severity: "high",
          impacted_providers: ["openai"],
          resources_fail: 1,
        },
      },
    ],
  });

  it("counts what is neither pass, fail nor muted as manual", () => {
    expect(overview).toMatchObject({ pass: 3, fail: 2, manual: 4 });
  });

  it("lists every AI vendor and says which ones are connected", () => {
    expect(
      overview.layers[0].providers.map(({ name, scope, connected }) => [
        name,
        scope,
        connected,
      ]),
    ).toEqual([
      ["Claude", "0 accounts", false],
      ["OpenAI", "2 accounts", true],
      ["ChatGPT", "0 accounts", false],
    ]);
  });

  it("groups each framework's requirements by section", () => {
    expect(overview.frameworks[0].sections).toEqual([
      { code: "LLM01", name: "Prompt Injection", pass: 1, fail: 1, manual: 0 },
      {
        code: "LLM02",
        name: "Sensitive Information Disclosure",
        pass: 0,
        fail: 0,
        manual: 1,
      },
    ]);
  });

  it("names the provider and resources of each top risk", () => {
    expect(overview.topRisks).toEqual([
      {
        checkId: "apikey_rotated_regularly",
        title: "API keys are rotated",
        severity: "high",
        providerName: "OpenAI",
        affected: "1 resource",
      },
    ]);
  });
});
