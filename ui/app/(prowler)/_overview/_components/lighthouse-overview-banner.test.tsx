import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import { LIGHTHOUSE_OVERVIEW_BANNER_HREF } from "../_lib/lighthouse-banner";

import { LighthouseOverviewBanner } from "./lighthouse-overview-banner";

describe("LighthouseOverviewBanner", () => {
  it("renders Toni copy and opens a prompted chat when connected", () => {
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

  it("isolates its stacking so content never paints over the sticky navbar", () => {
    // Given / When: the banner's inner z-10 must stay scoped to the card —
    // without isolation it ties the sticky header's z-10 and wins by DOM order
    render(
      <LighthouseOverviewBanner href={LIGHTHOUSE_OVERVIEW_BANNER_HREF.CHAT} />,
    );

    // Then
    const card = screen
      .getByRole("link", { name: /Find and remediate what actually matters\./ })
      .querySelector("[data-slot='card']");
    expect(card).toHaveClass("isolate");
  });
});
