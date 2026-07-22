import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";

import type { LighthouseContextEnvelope } from "@/types/lighthouse-context";

import {
  LighthouseContextBadge,
  LighthouseContextControl,
} from "./context-chip";

describe("LighthouseContextControl", () => {
  it("should show enabled context as a pressed badge and explain disabling it", async () => {
    // Given
    const user = userEvent.setup();
    const onDisable = vi.fn();
    render(
      <LighthouseContextControl
        context={findingsContext()}
        pageLabel="Findings"
        enabled
        selectionCount={1}
        onDisable={onDisable}
        onEnable={vi.fn()}
      />,
    );
    const contextControl = screen.getByRole("button", {
      name: "Disable Findings context",
    });

    // When
    await user.hover(contextControl);

    // Then
    expect(contextControl).toHaveAttribute("aria-pressed", "true");
    expect(contextControl).toHaveTextContent("@ Findings +1");
    expect(await screen.findByRole("tooltip")).toHaveTextContent(
      "Click to stop including Findings context in new messages.",
    );

    // When
    await user.click(contextControl);

    // Then
    expect(onDisable).toHaveBeenCalledOnce();
  });

  it("should keep the same badge label when disabled and explain enabling it", async () => {
    // Given
    const user = userEvent.setup();
    const onEnable = vi.fn();
    render(
      <LighthouseContextControl
        context={findingsContext()}
        pageLabel="Findings"
        enabled={false}
        selectionCount={1}
        onDisable={vi.fn()}
        onEnable={onEnable}
      />,
    );
    const contextControl = screen.getByRole("button", {
      name: "Enable Findings context",
    });

    // When
    await user.hover(contextControl);

    // Then
    expect(contextControl).toHaveAttribute("aria-pressed", "false");
    expect(contextControl).toHaveTextContent("@ Findings +1");
    expect(
      screen.queryByText("+ Add Findings context"),
    ).not.toBeInTheDocument();
    expect(await screen.findByRole("tooltip")).toHaveTextContent(
      "Click to include Findings context in new messages.",
    );

    // When
    await user.click(contextControl);

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
    ],
  };
}
