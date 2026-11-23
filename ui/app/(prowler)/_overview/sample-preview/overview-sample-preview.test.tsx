import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";

import {
  SAMPLE_SERVICES_RESPONSE,
  SAMPLE_STATUS,
} from "@/lib/sample-preview/sample-overview";

import { OverviewSamplePreview } from "./overview-sample-preview";

const { pushMock } = vi.hoisted(() => ({ pushMock: vi.fn() }));

// Card links import server actions; their auth chain has no place in jsdom.
vi.mock("next/navigation", () => ({
  useRouter: () => ({ push: pushMock, refresh: vi.fn() }),
  usePathname: () => "/",
  useSearchParams: () => new URLSearchParams(),
}));
vi.mock("@/auth.config", () => ({ auth: vi.fn() }));

// The graph tabs have their own test; here they would only add chart noise.
vi.mock("./sample-graphs-tabs", () => ({
  SampleGraphsTabs: () => null,
}));

describe("OverviewSamplePreview", () => {
  it("renders the demo account's passing and failing totals", () => {
    render(<OverviewSamplePreview showIssues={false} />);

    const card = screen
      .getByText("Check Findings")
      .closest('[data-slot="card"]')!;
    expect(
      within(card as HTMLElement).getByText(
        SAMPLE_STATUS.fail.toLocaleString(),
      ),
    ).toBeVisible();
    expect(
      within(card as HTMLElement).getByText(
        SAMPLE_STATUS.pass.toLocaleString(),
      ),
    ).toBeVisible();
  });

  it("only leaves links live where the target page shows the sample", () => {
    const { container } = render(<OverviewSamplePreview showIssues={false} />);

    const links = Array.from(container.querySelectorAll("a"));
    expect(links.length).toBeGreaterThan(0);
    for (const link of links) {
      expect(link.getAttribute("href")).toMatch(
        /^\/(findings|issues|compliance|resources)(\?|$)/,
      );
    }
  });

  it("opens sample findings filtered by the selected service", async () => {
    const user = userEvent.setup();
    render(<OverviewSamplePreview showIssues={false} />);

    // The riskiest service of the demo account leads the watchlist.
    const riskiest = [...SAMPLE_SERVICES_RESPONSE.data].sort(
      (left, right) => right.attributes.fail - left.attributes.fail,
    )[0];
    await user.click(
      screen.getByRole("button", { name: new RegExp(riskiest.id, "i") }),
    );
    const url = new URL(pushMock.mock.calls[0][0], "https://prowler.test");
    expect(url.pathname).toBe("/findings");
    expect(url.searchParams.get("filter[service__in]")).toBe(riskiest.id);
    expect(url.searchParams.get("filter[status__in]")).toBe("FAIL");
  });
});
