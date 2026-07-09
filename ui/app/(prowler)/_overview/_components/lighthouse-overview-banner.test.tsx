import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import { LighthouseOverviewBanner } from "./lighthouse-overview-banner";

describe("LighthouseOverviewBanner", () => {
  it("renders Toni copy and links to Lighthouse when connected", () => {
    // Given / When
    render(<LighthouseOverviewBanner href="/lighthouse" />);

    // Then
    const link = screen.getByRole("link", {
      name: /Find and remediate which actually matters\./,
    });
    expect(link).toHaveAttribute("href", "/lighthouse");
    expect(link).toHaveTextContent("Lighthouse AI");
    expect(link).toHaveTextContent(
      "Find and remediate which actually matters.",
    );
  });

  it("links to Lighthouse settings when no connected configuration exists", () => {
    // Given / When
    render(<LighthouseOverviewBanner href="/lighthouse/settings" />);

    // Then
    expect(
      screen.getByRole("link", {
        name: /Find and remediate which actually matters\./,
      }),
    ).toHaveAttribute("href", "/lighthouse/settings");
  });
});
