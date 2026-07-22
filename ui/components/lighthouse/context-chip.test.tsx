import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it } from "vitest";

import type { LighthouseContextEnvelope } from "@/types/lighthouse-context";

import {
  LighthouseContextBadge,
  LighthouseCurrentContextBadge,
} from "./context-chip";

describe("LighthouseCurrentContextBadge", () => {
  it("should show current context as read-only and explain automatic inclusion", async () => {
    // Given
    const user = userEvent.setup();
    render(<LighthouseCurrentContextBadge context={findingsContext()} />);
    const contextBadge = screen.getByLabelText("Findings context");

    // When
    await user.hover(contextBadge);

    // Then
    expect(
      screen.queryByRole("button", { name: /Findings context/ }),
    ).not.toBeInTheDocument();
    const tooltip = await screen.findByRole("tooltip");
    expect(contextBadge).toHaveTextContent("@ Findings +2");
    expect(tooltip).toHaveTextContent("Filters: severity: critical");
    expect(tooltip).toHaveTextContent("Finding: finding-focused");
    expect(tooltip).toHaveTextContent("Finding: finding-1");
  });

  it.each([
    ["resource", resourceContext(), "Resource: resource-1 (bucket-1)"],
    ["scan", scanContext(), "Scan: scan-1"],
    ["Attack Path", attackPathContext(), "Attack Path: query-1 (scan scan-1)"],
  ])("should identify included %s context", async (_, context, expected) => {
    // Given
    const user = userEvent.setup();
    render(<LighthouseCurrentContextBadge context={context} />);

    // When
    await user.hover(
      screen.getByLabelText(`${context.items[0].label} context`),
    );

    // Then
    expect(await screen.findByRole("tooltip")).toHaveTextContent(expected);
  });
});

describe("LighthouseContextBadge", () => {
  it("should render historical context as read-only", () => {
    // Given / When
    render(<LighthouseContextBadge context={findingsContext()} />);

    // Then
    expect(screen.getByText("@ Findings +2")).toBeInTheDocument();
    expect(
      screen.queryByRole("button", { name: /Findings context/ }),
    ).not.toBeInTheDocument();
  });
});

function findingsContext(): LighthouseContextEnvelope {
  return {
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
      {
        kind: "finding",
        id: "finding-1",
        source: "selection",
        scopeKey: "findings:/findings",
        label: "Selected finding",
        findingId: "finding-1",
      },
      {
        kind: "finding",
        id: "finding-focused",
        source: "focused",
        scopeKey: "findings:/findings",
        label: "Focused finding",
        findingId: "finding-focused",
        checkId: "aws_s3_bucket_public_access",
      },
    ],
  };
}

function resourceContext(): LighthouseContextEnvelope {
  return {
    schemaVersion: 1,
    transport: "inline",
    items: [
      {
        kind: "page",
        id: "resources",
        source: "automatic",
        scopeKey: "resources:/resources",
        label: "Resources",
        path: "/resources",
      },
      {
        kind: "resource",
        id: "resource-1",
        source: "focused",
        scopeKey: "resources:/resources",
        label: "Focused resource",
        resourceId: "resource-1",
        resourceUid: "bucket-1",
      },
    ],
  };
}

function scanContext(): LighthouseContextEnvelope {
  return {
    schemaVersion: 1,
    transport: "inline",
    items: [
      {
        kind: "page",
        id: "scans",
        source: "automatic",
        scopeKey: "scans:/scans",
        label: "Scans",
        path: "/scans",
        filters: { scanId: ["scan-1"] },
      },
      {
        kind: "scan",
        id: "scan-1",
        source: "selection",
        scopeKey: "scans:/scans",
        label: "Selected scan",
        scanId: "scan-1",
      },
    ],
  };
}

function attackPathContext(): LighthouseContextEnvelope {
  return {
    schemaVersion: 1,
    transport: "inline",
    items: [
      {
        kind: "page",
        id: "attack-paths",
        source: "automatic",
        scopeKey: "attack-paths:/attack-paths",
        label: "Attack Paths",
        path: "/attack-paths",
        filters: { scanId: ["scan-1"] },
      },
      {
        kind: "attack_path",
        id: "current-query",
        source: "automatic",
        scopeKey: "attack-paths:/attack-paths",
        label: "Internet-exposed resources",
        scanId: "scan-1",
        queryId: "query-1",
      },
    ],
  };
}
