import { render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";

import { SAMPLE_SERVICES_RESPONSE } from "@/lib/sample-preview/sample-overview";

import { OverviewSamplePreview } from "./overview-sample-preview";

// Card links import server actions; their auth chain has no place in jsdom.
vi.mock("next/navigation", () => ({
  useRouter: () => ({ push: vi.fn(), refresh: vi.fn() }),
  usePathname: () => "/",
  useSearchParams: () => new URLSearchParams(),
}));
vi.mock("@/auth.config", () => ({ auth: vi.fn() }));

// The graph tabs have their own test; here they would only add chart noise.
vi.mock("./sample-graphs-tabs", () => ({
  SampleGraphsTabs: () => <div data-testid="sample-graphs-tabs" />,
}));

describe("OverviewSamplePreview", () => {
  it("fills the Overview with the demo account's numbers", () => {
    render(<OverviewSamplePreview showIssues={false} />);

    expect(screen.getByText("Findings Severity Over Time")).toBeVisible();
    expect(screen.getByText("Internet Exposed Resources")).toBeVisible();
    expect(screen.getByTestId("sample-graphs-tabs")).toBeInTheDocument();
  });

  it("keeps every sample card inert, so nothing drills into missing data", () => {
    const { container } = render(<OverviewSamplePreview showIssues={false} />);

    const links = Array.from(container.querySelectorAll("a"));
    expect(links.length).toBeGreaterThan(0);
    for (const link of links) {
      expect(link.closest("[inert]")).not.toBeNull();
    }
  });

  it("lists every sample service in the watchlist", () => {
    render(<OverviewSamplePreview showIssues={false} />);

    // The riskiest service of the demo account leads the watchlist.
    const riskiest = [...SAMPLE_SERVICES_RESPONSE.data].sort(
      (left, right) => right.attributes.fail - left.attributes.fail,
    )[0];
    expect(
      screen.getAllByText(new RegExp(riskiest.id, "i")).length,
    ).toBeGreaterThan(0);
  });
});
