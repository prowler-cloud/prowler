import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";

import { HeatmapChart } from "./heatmap-chart";

vi.mock("next-themes", () => ({
  useTheme: () => ({ theme: "light" }),
}));

describe("HeatmapChart", () => {
  it("portals its pointer-positioned tooltip outside layout containers", async () => {
    // Given
    const user = userEvent.setup();
    const { container } = render(
      <HeatmapChart
        categories={[
          {
            name: "identity",
            failurePercentage: 25,
            totalRequirements: 4,
            failedRequirements: 1,
          },
        ]}
      />,
    );

    // When
    await user.hover(screen.getByTitle("Identity"));

    // Then: fixed client coordinates resolve against the viewport, not <main>
    const tooltip = screen.getByRole("tooltip");
    expect(container).not.toContainElement(tooltip);
    expect(tooltip.parentElement).toBe(document.body);
  });
});
