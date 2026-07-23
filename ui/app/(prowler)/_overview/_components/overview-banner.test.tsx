import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import { DOCS_URLS } from "@/lib/external-urls";

import { LIGHTHOUSE_OVERVIEW_BANNER_HREF } from "../_lib/lighthouse-banner";
import { OVERVIEW_BANNER_VARIANT } from "../_lib/overview-banner";

import { OverviewBanner } from "./overview-banner";

describe("OverviewBanner", () => {
  it("renders Toni copy and opens a prompted chat when connected", () => {
    // Given / When
    render(
      <OverviewBanner
        variant={OVERVIEW_BANNER_VARIANT.LIGHTHOUSE}
        href={LIGHTHOUSE_OVERVIEW_BANNER_HREF.CHAT}
      />,
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
      <OverviewBanner
        variant={OVERVIEW_BANNER_VARIANT.LIGHTHOUSE}
        href={LIGHTHOUSE_OVERVIEW_BANNER_HREF.SETTINGS}
      />,
    );

    // Then
    const link = screen.getByRole("link", {
      name: /Find and remediate what actually matters\./,
    });
    expect(link).toHaveAttribute("href", "/lighthouse/settings");
    // In-app hrefs stay in the current tab
    expect(link).not.toHaveAttribute("target");
  });

  it("opens the AI agents docs in a new tab", () => {
    // Given / When
    render(
      <OverviewBanner
        variant={OVERVIEW_BANNER_VARIANT.AGENTS}
        href={DOCS_URLS.AI_AGENTS}
      />,
    );

    // Then
    const link = screen.getByRole("link", {
      name: /Connect all your agents to Prowler Cloud/,
    });
    expect(link).toHaveAttribute("href", DOCS_URLS.AI_AGENTS);
    expect(link).toHaveAttribute("target", "_blank");
    expect(link).toHaveAttribute("rel", "noopener noreferrer");
    expect(link).toHaveTextContent(
      "Turn your favorite agent into a Cloud Security Expert.",
    );
  });

  it("uses the purple agents palette with the same animated layers", () => {
    // Given / When
    render(
      <OverviewBanner
        variant={OVERVIEW_BANNER_VARIANT.AGENTS}
        href={DOCS_URLS.AI_AGENTS}
      />,
    );

    // Then
    const link = screen.getByRole("link", {
      name: /Connect all your agents to Prowler Cloud/,
    });
    const gradient = link.querySelector(".overview-banner-gradient");
    expect(gradient).toHaveClass("overview-banner-gradient-agents");
    expect(gradient?.querySelector(".animate-first")).toBeInTheDocument();
    expect(gradient?.querySelector(".animate-second")).toBeInTheDocument();
    expect(gradient?.querySelector(".animate-third")).toBeInTheDocument();
    expect(
      gradient?.querySelector(".overview-banner-gradient-primary-press"),
    ).toBeInTheDocument();
  });

  it("keeps the Lighthouse banner on the default green palette", () => {
    // Given / When
    render(
      <OverviewBanner
        variant={OVERVIEW_BANNER_VARIANT.LIGHTHOUSE}
        href={LIGHTHOUSE_OVERVIEW_BANNER_HREF.CHAT}
      />,
    );

    // Then
    const link = screen.getByRole("link", {
      name: /Find and remediate what actually matters\./,
    });
    const gradient = link.querySelector(".overview-banner-gradient");
    expect(gradient).not.toHaveClass("overview-banner-gradient-agents");
  });

  it("scopes the blur filter id per instance so stacked banners keep their gradient", () => {
    // Given / When: url(#id) resolves against the FIRST match in the document,
    // so two banners sharing one id would both resolve to the same filter
    const { container } = render(
      <>
        <OverviewBanner
          variant={OVERVIEW_BANNER_VARIANT.LIGHTHOUSE}
          href={LIGHTHOUSE_OVERVIEW_BANNER_HREF.CHAT}
        />
        <OverviewBanner
          variant={OVERVIEW_BANNER_VARIANT.AGENTS}
          href={DOCS_URLS.AI_AGENTS}
        />
      </>,
    );

    // Then
    const filterIds = Array.from(
      container.querySelectorAll("filter"),
      (filter) => filter.id,
    );
    expect(filterIds).toHaveLength(2);
    expect(new Set(filterIds).size).toBe(2);
  });

  it("isolates its stacking so content never paints over the sticky navbar", () => {
    // Given / When: the banner's inner z-10 must stay scoped to the card —
    // without isolation it ties the sticky header's z-10 and wins by DOM order
    render(
      <OverviewBanner
        variant={OVERVIEW_BANNER_VARIANT.LIGHTHOUSE}
        href={LIGHTHOUSE_OVERVIEW_BANNER_HREF.CHAT}
      />,
    );

    // Then
    const card = screen
      .getByRole("link", { name: /Find and remediate what actually matters\./ })
      .querySelector("[data-slot='card']");
    expect(card).toHaveClass("isolate");
  });
});
