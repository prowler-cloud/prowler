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
    expect(contextBadge).toHaveTextContent("@ Findings +1");
    expect(
      screen.queryByRole("button", { name: /Findings context/ }),
    ).not.toBeInTheDocument();
    expect(await screen.findByRole("tooltip")).toHaveTextContent(
      "Findings context will be included in your next message.",
    );
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
