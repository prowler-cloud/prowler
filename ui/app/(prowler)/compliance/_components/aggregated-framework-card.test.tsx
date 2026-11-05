import { render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";

import { AggregatedFrameworkCard } from "./aggregated-framework-card";

describe("AggregatedFrameworkCard", () => {
  it("keeps the logo canvas light in dark mode", () => {
    // Given / When
    render(
      <AggregatedFrameworkCard
        frameworkTitle="CIS"
        formattedTitle="CIS"
        ariaLabel="Open CIS"
        onActivate={vi.fn()}
        subtitle={<span>Framework summary</span>}
      >
        <span>Framework details</span>
      </AggregatedFrameworkCard>,
    );

    // Then
    const logoCanvas = screen.getByRole("img", {
      name: "CIS logo",
    }).parentElement;
    expect(logoCanvas).toHaveClass("bg-slate-50");
    expect(logoCanvas).not.toHaveClass("bg-bg-neutral-tertiary");
  });

  it("keeps card actions outside the navigation control", () => {
    // Given
    render(
      <AggregatedFrameworkCard
        frameworkTitle="custom-framework"
        formattedTitle="Custom Framework"
        ariaLabel="Open Custom Framework"
        onActivate={vi.fn()}
        subtitle={<span>Framework summary</span>}
        actions={<button type="button">Pin framework</button>}
      >
        <span>Framework details</span>
      </AggregatedFrameworkCard>,
    );

    // When
    const navigation = screen.getByRole("button", {
      name: "Open Custom Framework",
    });
    const action = screen.getByRole("button", { name: "Pin framework" });

    // Then
    expect(navigation).not.toContainElement(action);
  });
});
