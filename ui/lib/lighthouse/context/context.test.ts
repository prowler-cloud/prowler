import { describe, expect, it } from "vitest";

import { compileLighthouseContext, prepareLighthouseContext } from "./compiler";
import {
  buildComplianceContext,
  buildFilteredProviderContext,
  buildFindingSeveritySummaryContext,
  buildFindingStatusSummaryContext,
  buildProviderGroupContext,
  buildServiceSummaryContext,
} from "./contributions";
import { buildLighthousePageContext } from "./pages";
import { lighthouseContextEnvelopeSchema } from "./schema";
import { getApiLighthouseContextByteLength } from "./transport";

describe("lighthouseContextEnvelopeSchema", () => {
  describe("when validating an inline page context", () => {
    it("should accept a valid version 1 envelope", () => {
      // Given
      const envelope = {
        schemaVersion: 1,
        transport: "inline",
        items: [
          {
            kind: "page",
            id: "findings",
            source: "automatic",
            scopeKey: "findings:/findings",
            label: "Findings",
            path: "/findings",
            filters: { severity: ["critical"] },
          },
        ],
      };

      // When
      const result = lighthouseContextEnvelopeSchema.safeParse(envelope);

      // Then
      expect(result.success).toBe(true);
    });

    it("should accept every supported contextual item kind", () => {
      // Given
      const envelope = {
        schemaVersion: 1,
        transport: "inline",
        items: [
          {
            kind: "finding",
            id: "finding-1",
            source: "selection",
            scopeKey: "findings:/findings",
            label: "Selected finding",
            findingId: "finding-1",
            checkId: "check-1",
            severity: "critical",
          },
          {
            kind: "resource",
            id: "resource-1",
            source: "selection",
            scopeKey: "resources:/resources",
            label: "Selected resource",
            resourceId: "resource-1",
            service: "s3",
            failedFindingsCount: 4,
          },
          {
            kind: "compliance",
            id: "cis-1.5",
            source: "automatic",
            scopeKey: "compliance:/compliance",
            label: "CIS 1.5",
            framework: "cis_1.5_aws",
            score: 82,
            totals: { passed: 82, failed: 18, total: 100 },
          },
          {
            kind: "attack_path",
            id: "query-1",
            source: "automatic",
            scopeKey: "attack-paths:/attack-paths/query-builder",
            label: "Attack path query",
            scanId: "scan-1",
            queryId: "query-1",
            parameters: { region: "eu-west-1", limit: 10 },
            nodeCount: 12,
            edgeCount: 11,
          },
          {
            kind: "scan",
            id: "scans-summary",
            source: "automatic",
            scopeKey: "scans:/scans",
            label: "Visible scans",
            total: 25,
          },
          {
            kind: "provider",
            id: "providers-summary",
            source: "automatic",
            scopeKey: "providers:/providers",
            label: "Visible providers",
            total: 7,
          },
        ],
      };

      // When
      const result = lighthouseContextEnvelopeSchema.safeParse(envelope);

      // Then
      expect(result.success).toBe(true);
    });
  });

  describe("when context exceeds transport limits", () => {
    it("should reject filters containing more than 20 values", () => {
      // Given
      const envelope = {
        schemaVersion: 1,
        transport: "inline",
        items: [
          {
            kind: "page",
            id: "findings",
            source: "automatic",
            scopeKey: "findings:/findings",
            label: "Findings",
            path: "/findings",
            filters: {
              severity: Array.from({ length: 21 }, (_, index) => `${index}`),
            },
          },
        ],
      };

      // When
      const result = lighthouseContextEnvelopeSchema.safeParse(envelope);

      // Then
      expect(result.success).toBe(false);
    });

    it("should reject more than twelve context items", () => {
      // Given
      const item = {
        kind: "page",
        id: "findings",
        source: "automatic",
        scopeKey: "findings:/findings",
        label: "Findings",
        path: "/findings",
      };

      // When
      const result = lighthouseContextEnvelopeSchema.safeParse({
        schemaVersion: 1,
        transport: "inline",
        items: Array.from({ length: 13 }, (_, index) => ({
          ...item,
          id: `page-${index}`,
        })),
      });

      // Then
      expect(result.success).toBe(false);
    });

    it("should reject strings longer than 256 characters", () => {
      // Given / When
      const result = lighthouseContextEnvelopeSchema.safeParse({
        schemaVersion: 1,
        transport: "inline",
        items: [
          {
            kind: "page",
            id: "findings",
            source: "automatic",
            scopeKey: "findings:/findings",
            label: "x".repeat(257),
            path: "/findings",
          },
        ],
      });

      // Then
      expect(result.success).toBe(false);
    });

    it("should reject unknown item kinds", () => {
      // Given / When
      const result = lighthouseContextEnvelopeSchema.safeParse({
        schemaVersion: 1,
        transport: "inline",
        items: [
          {
            kind: "secret",
            id: "credentials",
            source: "automatic",
            scopeKey: "findings:/findings",
            label: "Credentials",
          },
        ],
      });

      // Then
      expect(result.success).toBe(false);
    });
  });
});

describe("compileLighthouseContext", () => {
  describe("when multiple contributors describe the same entity", () => {
    it("should deduplicate items by kind and id", () => {
      // Given
      const scopeKey = "findings:/findings";
      const items = [
        {
          kind: "page",
          id: "findings",
          source: "automatic",
          scopeKey,
          label: "Findings",
          path: "/findings",
        },
        {
          kind: "finding",
          id: "finding-1",
          source: "selection",
          scopeKey,
          label: "Selected finding",
          findingId: "finding-1",
          severity: "critical",
        },
        {
          kind: "finding",
          id: "finding-1",
          source: "selection",
          scopeKey,
          label: "Duplicate finding",
          findingId: "finding-1",
          severity: "critical",
        },
      ];

      // When
      const context = compileLighthouseContext(items, scopeKey);

      // Then
      expect(context?.items.map((item) => `${item.kind}:${item.id}`)).toEqual([
        "page:findings",
        "finding:finding-1",
      ]);
    });

    it("should retain the highest-priority duplicate", () => {
      // Given
      const scopeKey = "findings:/findings";
      const items = [
        {
          kind: "page",
          id: "findings",
          source: "automatic",
          scopeKey,
          label: "Findings",
          path: "/findings",
        },
        {
          kind: "finding",
          id: "finding-1",
          source: "selection",
          scopeKey,
          label: "Selected finding",
          findingId: "finding-1",
        },
        {
          kind: "finding",
          id: "finding-1",
          source: "focused",
          scopeKey,
          label: "Focused finding",
          findingId: "finding-1",
        },
      ];

      // When
      const context = compileLighthouseContext(items, scopeKey);

      // Then
      expect(context?.items[1]).toMatchObject({
        id: "finding-1",
        source: "focused",
        label: "Focused finding",
      });
    });
  });

  describe("when contributors arrive in render order", () => {
    it("should order page, focused, selection, and summary items deterministically", () => {
      // Given
      const scopeKey = "findings:/findings";
      const items = [
        {
          kind: "finding",
          id: "findings-summary",
          source: "automatic",
          scopeKey,
          label: "Visible findings",
          findingId: "summary",
          total: 42,
        },
        {
          kind: "finding",
          id: "finding-1",
          source: "selection",
          scopeKey,
          label: "Selected finding",
          findingId: "finding-1",
        },
        {
          kind: "finding",
          id: "finding-focused",
          source: "focused",
          scopeKey,
          label: "Focused finding",
          findingId: "finding-focused",
        },
        {
          kind: "page",
          id: "findings",
          source: "automatic",
          scopeKey,
          label: "Findings",
          path: "/findings",
        },
      ];

      // When
      const context = compileLighthouseContext(items, scopeKey);

      // Then
      expect(context?.items.map((item) => item.id)).toEqual([
        "findings",
        "finding-focused",
        "finding-1",
        "findings-summary",
      ]);
    });
  });

  describe("when serialized context exceeds the byte limit", () => {
    it("should drop lowest-priority items until the context fits", () => {
      // Given
      const scopeKey = "findings:/findings";
      const page = {
        kind: "page",
        id: "findings",
        source: "automatic",
        scopeKey,
        label: "Findings",
        path: "/findings",
      };
      const selection = {
        kind: "finding",
        id: "finding-1",
        source: "selection",
        scopeKey,
        label: "Selected finding",
        findingId: "finding-1",
      };
      const summaries = Array.from({ length: 6 }, (_, index) => ({
        kind: "finding",
        id: `summary-${index}`,
        source: "automatic",
        scopeKey,
        label: `Summary ${index} ${"x".repeat(240)}`,
        findingId: `summary-${index}`,
        checkId: `check-${index}-${"y".repeat(240)}`,
        providerUid: `provider-${index}-${"z".repeat(237)}`,
        total: index,
      }));

      // When
      const context = compileLighthouseContext(
        [page, selection, ...summaries],
        scopeKey,
      );

      // Then
      expect(context?.items.map((item) => item.id)).toEqual([
        "findings",
        "finding-1",
        "summary-0",
        "summary-1",
        "summary-2",
        "summary-3",
      ]);
    });

    it("should drop oversized selections while keeping the page", () => {
      // Given
      const scopeKey = "findings:/findings";
      const page = {
        kind: "page",
        id: "findings",
        source: "automatic",
        scopeKey,
        label: "Findings",
        path: "/findings",
      };
      const selections = Array.from({ length: 2 }, (_, index) => ({
        kind: "finding",
        id: `finding-${index}`,
        source: "selection",
        scopeKey,
        label: "x".repeat(256),
        findingId: "y".repeat(256),
        checkId: "z".repeat(256),
        severity: "s".repeat(256),
        status: "t".repeat(256),
        providerUid: "p".repeat(256),
        resourceUid: "r".repeat(256),
        region: "g".repeat(256),
      }));

      // When
      const context = compileLighthouseContext([...selections, page], scopeKey);

      // Then
      expect(context?.items.map((item) => item.id)).toEqual([
        "findings",
        "finding-0",
      ]);
    });
  });

  describe("when context exceeds the item limit", () => {
    it("should progressively drop only the lowest-priority items", () => {
      // Given
      const scopeKey = "findings:/findings";
      const page = {
        kind: "page",
        id: "findings",
        source: "automatic",
        scopeKey,
        label: "Findings",
        path: "/findings",
      };
      const focused = {
        kind: "finding",
        id: "focused",
        source: "focused",
        scopeKey,
        label: "Focused finding",
        findingId: "focused",
      };
      const selections = Array.from({ length: 2 }, (_, index) => ({
        kind: "finding",
        id: `selection-${index}`,
        source: "selection",
        scopeKey,
        label: `Selected finding ${index}`,
        findingId: `selection-${index}`,
      }));
      const summaries = Array.from({ length: 12 }, (_, index) => ({
        kind: "finding",
        id: `summary-${index}`,
        source: "automatic",
        scopeKey,
        label: `Summary ${index}`,
        findingId: `summary-${index}`,
        total: index,
      }));

      // When
      const context = compileLighthouseContext(
        [page, ...summaries, ...selections, focused],
        scopeKey,
      );

      // Then
      expect(context?.items.map((item) => item.id)).toEqual([
        "findings",
        "focused",
        "selection-0",
        "selection-1",
        "summary-0",
        "summary-1",
        "summary-2",
        "summary-3",
        "summary-4",
        "summary-5",
        "summary-6",
        "summary-7",
      ]);
    });
  });

  describe("when the Overview publishes every contributor", () => {
    it("should fit a fully populated Overview within transport limits", () => {
      // Given every real Overview contributor plus the page item
      const candidates = [
        buildLighthousePageContext(
          "/",
          new URLSearchParams(
            "filter[provider_id__in]=b81165a0-4f28-4b5c-9a41-1e2d3c4b5a69&filter[provider_type__in]=aws",
          ),
        ),
        buildComplianceContext({
          pathname: "/",
          id: "prowler-threat-score",
          framework: "Prowler ThreatScore",
          score: 62.4,
          scoreDelta: -3.21,
          criticalRequirementsCount: 5,
          worstSection: "1.2 Attack Surface",
          worstSectionScore: 38.6,
          passed: 120,
          failed: 40,
          total: 160,
        }),
        buildFindingStatusSummaryContext({
          pathname: "/",
          passed: 320,
          failed: 80,
          newPassed: 12,
          newFailed: 7,
        }),
        buildFindingSeveritySummaryContext({
          pathname: "/",
          severityCounts: {
            critical: 4,
            high: 18,
            medium: 40,
            low: 15,
            informational: 3,
          },
        }),
        buildComplianceContext({
          pathname: "/",
          id: "watchlist-ens_rd2022_aws",
          framework: "ENS RD2022",
          score: 30,
        }),
        buildComplianceContext({
          pathname: "/",
          id: "watchlist-cis_1.5_aws",
          framework: "CIS AWS 1.5",
          score: 45,
        }),
        buildServiceSummaryContext({
          pathname: "/",
          service: "s3",
          failedFindingsCount: 34,
          total: 120,
        }),
        buildFilteredProviderContext({
          pathname: "/",
          id: "b81165a0-4f28-4b5c-9a41-1e2d3c4b5a69",
          uid: "123456789012",
          type: "aws",
          alias: "Production",
        }),
        buildProviderGroupContext({
          pathname: "/",
          id: "3f2a1b0c-9d8e-7f60-5a4b-3c2d1e0f9a8b",
          name: "Production accounts",
        }),
      ];

      // When
      const context = compileLighthouseContext(candidates, "overview:/");

      // Then every real Overview contributor fits within the budget
      expect(context).toBeDefined();
      expect(context?.items).toHaveLength(candidates.length);
      expect(context?.items[0]?.kind).toBe("page");
      expect(context?.items.some((item) => item.id.startsWith("group-"))).toBe(
        true,
      );
      expect(getApiLighthouseContextByteLength(context!)).toBeLessThanOrEqual(
        4 * 1024,
      );
    });
  });

  describe("when contributors belong to another page", () => {
    it("should ignore stale scoped data", () => {
      // Given / When
      const context = compileLighthouseContext(
        [
          {
            kind: "page",
            id: "resources",
            source: "automatic",
            scopeKey: "resources:/resources",
            label: "Resources",
            path: "/resources",
          },
          {
            kind: "finding",
            id: "finding-1",
            source: "selection",
            scopeKey: "findings:/findings",
            label: "Old finding",
            findingId: "finding-1",
          },
        ],
        "resources:/resources",
      );

      // Then
      expect(context?.items.map((item) => item.id)).toEqual(["resources"]);
    });
  });

  describe("when current context is invalid", () => {
    it("should return no context so sending remains available", () => {
      // Given / When
      const context = compileLighthouseContext(
        [
          {
            kind: "finding",
            id: "finding-1",
            source: "selection",
            scopeKey: "findings:/findings",
            label: "Invalid finding without findingId",
          },
        ],
        "findings:/findings",
      );

      // Then
      expect(context).toBeUndefined();
    });

    it("should drop only the invalid item and keep the valid ones", () => {
      // Given a valid page plus a finding whose optional field was
      // normalized to null (e.g. by a backend or storage layer)
      const context = compileLighthouseContext(
        [
          {
            kind: "page",
            id: "findings",
            source: "automatic",
            scopeKey: "findings:/findings",
            label: "Findings",
            path: "/findings",
          },
          {
            kind: "finding",
            id: "finding-1",
            source: "selection",
            scopeKey: "findings:/findings",
            label: "Selected finding",
            findingId: "finding-1",
            checkId: null,
          },
          {
            kind: "finding",
            id: "finding-2",
            source: "selection",
            scopeKey: "findings:/findings",
            label: "Selected finding",
            findingId: "finding-2",
          },
        ],
        "findings:/findings",
      );

      // Then the null-carrying item drops alone
      expect(context?.items.map((item) => item.id)).toEqual([
        "findings",
        "finding-2",
      ]);
    });

    it("should drop items of unknown kinds without voiding the envelope", () => {
      // Given an item kind from a newer (or rolled-back) UI build
      const context = compileLighthouseContext(
        [
          {
            kind: "page",
            id: "findings",
            source: "automatic",
            scopeKey: "findings:/findings",
            label: "Findings",
            path: "/findings",
          },
          {
            kind: "future-widget",
            id: "widget-1",
            source: "automatic",
            scopeKey: "findings:/findings",
            label: "Unknown widget",
          },
        ],
        "findings:/findings",
      );

      // Then
      expect(context?.items.map((item) => item.id)).toEqual(["findings"]);
    });
  });

  describe("when automatic items compete for the byte budget", () => {
    it("should evict provider labels before posture summaries", () => {
      // Given a page, a ThreatScore summary, and enough oversized provider
      // labels to exceed the byte budget regardless of arrival order
      const scopeKey = "overview:/";
      const page = {
        kind: "page",
        id: "overview",
        source: "automatic",
        scopeKey,
        label: "Overview",
        path: "/",
      };
      const threatScore = {
        kind: "compliance",
        id: "prowler-threat-score",
        source: "automatic",
        scopeKey,
        label: "Prowler ThreatScore",
        framework: "Prowler ThreatScore",
        score: 62.4,
      };
      const providers = Array.from({ length: 10 }, (_, index) => ({
        kind: "provider",
        id: `provider-${index}`,
        source: "automatic",
        scopeKey,
        label: `Provider ${index} ${"x".repeat(240)}`,
        providerUid: `uid-${index}-${"y".repeat(240)}`,
      }));

      // When the providers mount before the ThreatScore summary
      const context = compileLighthouseContext(
        [page, ...providers, threatScore],
        scopeKey,
      );

      // Then the summary survives and only provider labels are evicted
      expect(context?.items.map((item) => item.kind)).toContain("compliance");
      expect(
        context?.items.filter((item) => item.kind === "provider").length,
      ).toBeLessThan(providers.length);
      expect(context?.items[1]?.id).toBe("prowler-threat-score");
    });
  });
});

describe("prepareLighthouseContext", () => {
  it("should keep the valid items when one carries a malformed optional", () => {
    // Given a stored envelope whose finding had checkId normalized to null
    const context = prepareLighthouseContext({
      schemaVersion: 1,
      transport: "inline",
      items: [
        {
          kind: "page",
          id: "findings",
          source: "automatic",
          scopeKey: "findings:/findings",
          label: "Findings",
          path: "/findings",
        },
        {
          kind: "finding",
          id: "finding-1",
          source: "selection",
          scopeKey: "findings:/findings",
          label: "Selected finding",
          findingId: "finding-1",
          checkId: null,
        },
      ],
    });

    // Then the malformed item drops alone instead of voiding the send
    expect(context?.items.map((item) => item.id)).toEqual(["findings"]);
  });

  it("should scope from the first usable item when the leading one is malformed", () => {
    // Given a leading item with no scopeKey at all
    const context = prepareLighthouseContext({
      schemaVersion: 1,
      transport: "inline",
      items: [
        { kind: "finding", id: "broken" },
        {
          kind: "page",
          id: "findings",
          source: "automatic",
          scopeKey: "findings:/findings",
          label: "Findings",
          path: "/findings",
        },
      ],
    });

    // Then the later valid page item still compiles
    expect(context?.items.map((item) => item.id)).toEqual(["findings"]);
  });

  it("should not let a malformed foreign-scope item decide the scope", () => {
    // Given a malformed leading item whose scopeKey points at another page
    const context = prepareLighthouseContext({
      schemaVersion: 1,
      transport: "inline",
      items: [
        { kind: "resource", id: "broken", scopeKey: "resources:/resources" },
        {
          kind: "page",
          id: "findings",
          source: "automatic",
          scopeKey: "findings:/findings",
          label: "Findings",
          path: "/findings",
        },
      ],
    });

    // Then the valid page defines the scope and compiles
    expect(context?.items.map((item) => item.scopeKey)).toEqual([
      "findings:/findings",
    ]);
  });

  it("should return no context for values without an item list", () => {
    expect(prepareLighthouseContext(undefined)).toBeUndefined();
    expect(prepareLighthouseContext({ items: "not-a-list" })).toBeUndefined();
    expect(prepareLighthouseContext({ items: [] })).toBeUndefined();
  });
});
