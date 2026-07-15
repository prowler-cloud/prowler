import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import { LighthouseOverviewBanner } from "./lighthouse-overview-banner";

const REMEDIATION_PROMPT =
  "Find and guide me to remediate which actually matters. What do I have to do today to be secure?";
const REMEDIATION_HREF = `/lighthouse?prompt=${encodeURIComponent(
  REMEDIATION_PROMPT,
)}` as const;

describe("LighthouseOverviewBanner", () => {
  it("renders Toni copy and links to Lighthouse when connected", () => {
    // Given / When
    render(<LighthouseOverviewBanner href={REMEDIATION_HREF} />);

    // Then
    const link = screen.getByRole("link", {
      name: /Find and remediate which actually matters\./,
    });
    expect(link).toHaveAttribute("href", REMEDIATION_HREF);
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
