import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import { LIGHTHOUSE_OVERVIEW_BANNER_HREF } from "../_lib/lighthouse-banner";
import { LighthouseOverviewBanner } from "./lighthouse-overview-banner";

describe("LighthouseOverviewBanner", () => {
  it("renders Toni copy and starts a prompted conversation when connected", () => {
    // Given / When
    render(
      <LighthouseOverviewBanner href={LIGHTHOUSE_OVERVIEW_BANNER_HREF.CHAT} />,
    );

    // Then
    const link = screen.getByRole("link", {
      name: /Find and remediate what actually matters\./,
    });
    expect(link).toHaveAttribute("href", LIGHTHOUSE_OVERVIEW_BANNER_HREF.CHAT);
    expect(link).toHaveTextContent("Lighthouse AI");
    expect(link).toHaveTextContent("Find and remediate what actually matters.");
  });

  it("links to Lighthouse settings when no connected configuration exists", () => {
    // Given / When
    render(
      <LighthouseOverviewBanner
        href={LIGHTHOUSE_OVERVIEW_BANNER_HREF.SETTINGS}
      />,
    );

    // Then
    expect(
      screen.getByRole("link", {
        name: /Find and remediate what actually matters\./,
      }),
    ).toHaveAttribute("href", "/lighthouse/settings");
  });
});
