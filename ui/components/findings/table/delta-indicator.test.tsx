import { render } from "@testing-library/react";
import type { ReactNode } from "react";
import { describe, expect, it, vi } from "vitest";

vi.mock("@/components/shadcn/tooltip", () => ({
  Tooltip: ({ children }: { children: ReactNode }) => <div>{children}</div>,
  TooltipTrigger: ({ children }: { children: ReactNode }) => <>{children}</>,
  TooltipContent: ({ children }: { children: ReactNode }) => (
    <div>{children}</div>
  ),
}));

import { DeltaIndicator } from "./delta-indicator";

describe("DeltaIndicator", () => {
  it("uses the design-system fail color for new findings", () => {
    // Given
    const { container } = render(<DeltaIndicator delta="new" />);

    // When
    const deltaDot = container.querySelector(".rounded-full");

    // Then
    expect(deltaDot).toHaveClass("bg-bg-fail");
  });

  it("uses the design-system warning color for changed findings", () => {
    // Given
    const { container } = render(<DeltaIndicator delta="changed" />);

    // When
    const deltaDot = container.querySelector(".rounded-full");

    // Then
    expect(deltaDot).toHaveClass("bg-bg-warning");
  });
});
