import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it } from "vitest";

import type { LighthouseContextEnvelope } from "@/types/lighthouse-context";

import {
  LighthouseContextBadge,
  LighthouseCurrentContextBadge,
} from "./context-chip";

describe("LighthouseCurrentContextBadge", () => {
  it.each([
    ["focused detail", resourceContext(), "@ Resources · Detail"],
    ["explicit selection", scanContext(), "@ Scans +1"],
    [
      "focused detail with a selection",
      findingsContext(),
      "@ Findings · Detail +1",
    ],
    ["automatic context", attackPathContext(), "@ Attack Paths"],
  ])("should label %s clearly", (_, context, expectedLabel) => {
    // Given / When
    render(<LighthouseCurrentContextBadge context={context} />);

    // Then
    expect(
      screen.getByLabelText(`${context.items[0].label} context`),
    ).toHaveTextContent(expectedLabel);
  });

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
    expect(contextBadge).toHaveTextContent("@ Findings · Detail +1");
    expect(tooltip).toHaveTextContent("Filters: severity: critical");
    expect(tooltip).toHaveTextContent("Finding: finding-focused");
    expect(tooltip).toHaveTextContent("Finding: finding-1");
  });

  it("should keep ambient automatic summaries out of the tooltip", async () => {
    // Given the Overview publishes a bit of everything automatically
    const user = userEvent.setup();
    render(<LighthouseCurrentContextBadge context={overviewContext()} />);

    // When
    await user.hover(screen.getByLabelText("Overview context"));

    // Then the tooltip names the page without enumerating page snapshots
    const tooltip = await screen.findByRole("tooltip");
    expect(tooltip).toHaveTextContent("Overview");
    expect(tooltip).not.toHaveTextContent("Prowler ThreatScore");
    expect(tooltip).not.toHaveTextContent("80 failed / 320 passed findings");
    expect(tooltip).not.toHaveTextContent("Failing findings by severity");
    expect(tooltip).not.toHaveTextContent("Service: cloudwatch");
    expect(tooltip).not.toHaveTextContent("status-summary");
  });

  it("should say when only the page name is shared", async () => {
    // Given an unregistered route contributes a bare, filterless page item
    const user = userEvent.setup();
    render(<LighthouseCurrentContextBadge context={barePageContext()} />);

    // When
    await user.hover(screen.getByLabelText("Manage Groups context"));

    // Then
    const tooltip = await screen.findByRole("tooltip");
    expect(tooltip).toHaveTextContent("Manage Groups");
    expect(tooltip).toHaveTextContent("Only the current page name is shared.");
  });

  it("should treat empty filter entries as a bare page", async () => {
    // Given a stored envelope whose page filters only carry empty values
    const user = userEvent.setup();
    const bareContext = barePageContext();
    const [pageItem] = bareContext.items;
    if (pageItem.kind !== "page") throw new Error("expected page item");
    render(
      <LighthouseCurrentContextBadge
        context={{
          ...bareContext,
          items: [{ ...pageItem, filters: { status: [] } }],
        }}
      />,
    );

    // When
    await user.hover(screen.getByLabelText("Manage Groups context"));

    // Then no filters line renders and the page-only notice does
    const tooltip = await screen.findByRole("tooltip");
    expect(tooltip).not.toHaveTextContent("Filters:");
    expect(tooltip).toHaveTextContent("Only the current page name is shared.");
  });

  it("should not claim a bare page for a single non-page item", async () => {
    // Given a historical envelope whose only item is not a page item
    const user = userEvent.setup();
    const context: LighthouseContextEnvelope = {
      schemaVersion: 1,
      transport: "inline",
      items: [
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
    render(<LighthouseCurrentContextBadge context={context} />);

    // When
    await user.hover(screen.getByLabelText("Context context"));

    // Then
    const tooltip = await screen.findByRole("tooltip");
    expect(tooltip).not.toHaveTextContent(
      "Only the current page name is shared.",
    );
  });

  it("should not claim a bare page when filters or items travel too", async () => {
    // Given
    const user = userEvent.setup();
    render(<LighthouseCurrentContextBadge context={findingsContext()} />);

    // When
    await user.hover(screen.getByLabelText("Findings context"));

    // Then
    const tooltip = await screen.findByRole("tooltip");
    expect(tooltip).not.toHaveTextContent(
      "Only the current page name is shared.",
    );
  });

  it.each([
    ["resource", resourceContext(), "Resource: resource-1 (bucket-1)"],
    ["scan", scanContext(), "Scan: scan-1"],
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
    expect(screen.getByText("@ Findings · Detail +1")).toBeInTheDocument();
    expect(
      screen.queryByRole("button", { name: /Findings context/ }),
    ).not.toBeInTheDocument();
  });
});

function barePageContext(): LighthouseContextEnvelope {
  return {
    schemaVersion: 1,
    transport: "inline",
    items: [
      {
        kind: "page",
        id: "other",
        source: "automatic",
        scopeKey: "other:/manage-groups",
        label: "Manage Groups",
        path: "/manage-groups",
      },
    ],
  };
}

function overviewContext(): LighthouseContextEnvelope {
  return {
    schemaVersion: 1,
    transport: "inline",
    items: [
      {
        kind: "page",
        id: "overview",
        source: "automatic",
        scopeKey: "overview:/",
        label: "Overview",
        path: "/",
      },
      {
        kind: "compliance",
        id: "prowler-threat-score",
        source: "automatic",
        scopeKey: "overview:/",
        label: "Prowler ThreatScore",
        framework: "Prowler ThreatScore",
        score: 62.4,
      },
      {
        kind: "finding",
        id: "status-summary",
        source: "automatic",
        scopeKey: "overview:/",
        label: "80 failed / 320 passed findings",
        findingId: "status-summary",
        passed: 320,
        failed: 80,
      },
      {
        kind: "finding",
        id: "severity-summary",
        source: "automatic",
        scopeKey: "overview:/",
        label: "Failing findings by severity",
        findingId: "severity-summary",
        severityCounts: { critical: 4 },
      },
      {
        kind: "resource",
        id: "service-cloudwatch",
        source: "automatic",
        scopeKey: "overview:/",
        label: "Service: cloudwatch",
        resourceId: "service-cloudwatch",
        service: "cloudwatch",
        failedFindingsCount: 34,
      },
    ],
  };
}

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
