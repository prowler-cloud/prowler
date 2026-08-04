import { render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";

import { AggregatedFrameworkCard } from "./aggregated-framework-card";

describe("AggregatedFrameworkCard", () => {
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
