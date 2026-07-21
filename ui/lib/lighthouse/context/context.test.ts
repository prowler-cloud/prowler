import { describe, expect, it } from "vitest";

import { compileLighthouseContext } from "./compiler";
import { lighthouseContextEnvelopeSchema } from "./schema";

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

    it("should reject more than eight context items", () => {
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
        items: Array.from({ length: 9 }, (_, index) => ({
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
  });

  describe("when contributors arrive in render order", () => {
    it("should order page, selection, and summary items deterministically", () => {
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
        "finding-1",
        "findings-summary",
      ]);
    });
  });

  describe("when serialized context exceeds 2 KiB", () => {
    it("should remove automatic summaries before dropping the selection", () => {
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
      ]);
    });

    it("should preserve only the page when selection data is still too large", () => {
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
        label: "x".repeat(256),
        findingId: "y".repeat(256),
        checkId: "z".repeat(256),
        severity: "s".repeat(256),
        status: "t".repeat(256),
        providerUid: "p".repeat(256),
        resourceUid: "r".repeat(256),
        region: "g".repeat(256),
      };

      // When
      const context = compileLighthouseContext([selection, page], scopeKey);

      // Then
      expect(context?.items.map((item) => item.id)).toEqual(["findings"]);
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

    it("should discard valid items together with an invalid same-scope item", () => {
      // Given / When
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
            label: "Invalid finding without findingId",
          },
        ],
        "findings:/findings",
      );

      // Then
      expect(context).toBeUndefined();
    });
  });
});
