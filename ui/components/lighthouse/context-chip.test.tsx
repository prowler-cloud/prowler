import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";

import type { LighthouseContextEnvelope } from "@/types/lighthouse-context";

import {
  LighthouseContextBadge,
  LighthouseContextControl,
} from "./context-chip";

describe("LighthouseContextControl", () => {
  it("should show the current page, selection count, and accessible details", async () => {
    // Given
    const user = userEvent.setup();
    render(
      <LighthouseContextControl
        context={findingsContext()}
        pageLabel="Findings"
        enabled
        selectionCount={1}
        onDisable={vi.fn()}
        onEnable={vi.fn()}
      />,
    );

    // When
    await user.hover(screen.getByText("@ Findings +1"));

    // Then
    expect(await screen.findByRole("tooltip")).toHaveTextContent(
      "Filters: severity: critical",
    );
    expect(screen.getByRole("tooltip")).toHaveTextContent(
      "Included types: page, finding",
    );
  });

  it("should disable and restore context through explicit actions", async () => {
    // Given
    const user = userEvent.setup();
    const onDisable = vi.fn();
    const onEnable = vi.fn();
    const view = render(
      <LighthouseContextControl
        context={findingsContext()}
        pageLabel="Findings"
        enabled
        selectionCount={1}
        onDisable={onDisable}
        onEnable={onEnable}
      />,
    );

    // When
    await user.click(
      screen.getByRole("button", { name: "Remove Findings context" }),
    );

    // Then
    expect(onDisable).toHaveBeenCalledOnce();

    // Given
    view.rerender(
      <LighthouseContextControl
        context={findingsContext()}
        pageLabel="Findings"
        enabled={false}
        selectionCount={1}
        onDisable={onDisable}
        onEnable={onEnable}
      />,
    );

    // When
    await user.click(
      screen.getByRole("button", { name: "Add Findings context" }),
    );

    // Then
    expect(onEnable).toHaveBeenCalledOnce();
  });
});

describe("LighthouseContextBadge", () => {
  it("should render historical context as read-only", () => {
    // Given / When
    render(<LighthouseContextBadge context={findingsContext()} />);

    // Then
    expect(screen.getByText("@ Findings +1")).toBeInTheDocument();
    expect(
      screen.queryByRole("button", { name: /Remove Findings context/ }),
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
    ],
  };
}
