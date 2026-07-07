import { render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";

import type { CrossProviderInsights } from "@/lib/compliance/cross-provider-insights";
import { getProwlerHubComplianceUrl } from "@/lib/compliance/prowler-hub";

import { CrossProviderHeader } from "./cross-provider-header";

vi.mock("next/image", () => ({
  default: ({ alt }: { alt?: string }) => <span aria-label={alt} />,
}));

// The three data panes have their own tests; stub them so this suite renders
// only the header's metadata strip + Prowler Hub link wiring.
vi.mock("./provider-coverage-panel", () => ({
  ProviderCoveragePanel: () => <div />,
}));
vi.mock("./score-donut", () => ({ ScoreDonut: () => <div /> }));
vi.mock("./top-failing-domains-panel", () => ({
  TopFailingDomainsPanel: () => <div />,
}));

const insights = {} as CrossProviderInsights;

const baseProps = {
  framework: "CSA-CCM",
  name: "CSA Cloud Controls Matrix",
  version: "4.0",
  description: "A universal framework",
  complianceId: "csa_ccm_4.0",
  insights,
};

describe("CrossProviderHeader", () => {
  it("renders the framework name and version", () => {
    render(<CrossProviderHeader {...baseProps} />);

    expect(screen.getByText("CSA Cloud Controls Matrix")).toBeInTheDocument();
    expect(screen.getByText("v4.0")).toBeInTheDocument();
  });

  it("links to the framework's Prowler Hub page", () => {
    render(<CrossProviderHeader {...baseProps} />);

    const hubLink = screen.getByRole("link", { name: /prowler hub/i });
    expect(hubLink).toHaveAttribute(
      "href",
      getProwlerHubComplianceUrl(baseProps.complianceId),
    );
  });

  it("opens the Prowler Hub link in a new, referrer-stripped tab", () => {
    render(<CrossProviderHeader {...baseProps} />);

    const hubLink = screen.getByRole("link", { name: /prowler hub/i });
    expect(hubLink).toHaveAttribute("target", "_blank");
    // ``noopener`` blocks the opened tab from reaching back via
    // ``window.opener``; ``noreferrer`` strips the referrer header.
    expect(hubLink).toHaveAttribute("rel", "noopener noreferrer");
  });
});
