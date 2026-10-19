import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";

import { VerdictFilter } from "@/components/issues/verdict-filter";

const navigationState = vi.hoisted(() => ({
  searchParams: new URLSearchParams(),
  push: vi.fn(),
}));

vi.mock("next/navigation", () => ({
  usePathname: () => "/issues",
  useRouter: () => ({ push: navigationState.push }),
  useSearchParams: () => navigationState.searchParams,
}));

vi.mock("@/contexts", () => ({ useFilterTransitionOptional: () => null }));

const counts = {
  exploitable: 2,
  likely: 0,
  conditional: 0,
  not_exploitable: 0,
  unknown: 0,
};

const lastPushedParams = () =>
  new URL(navigationState.push.mock.calls.at(-1)![0], "http://localhost")
    .searchParams;

describe("VerdictFilter", () => {
  it("renders one tab per verdict with its count and the fold", () => {
    navigationState.searchParams = new URLSearchParams();
    render(<VerdictFilter summary={{ counts, total: 2, findings: 9 }} />);

    expect(screen.getByRole("tab", { name: "All, 2 issues" })).toHaveAttribute(
      "aria-selected",
      "true",
    );
    expect(
      screen.getByRole("tab", { name: "Exploitable, 2 issues" }),
    ).toHaveAttribute("aria-selected", "false");
    expect(screen.getAllByRole("tab")).toHaveLength(6);
    expect(
      screen.getByText("9 failed findings folded into 2 issues"),
    ).toBeInTheDocument();
  });

  it("selects the verdict tab and resets the page, keeping other params", async () => {
    const user = userEvent.setup();
    navigationState.searchParams = new URLSearchParams(
      "page=3&pageSize=10&filter[verdict]=likely",
    );
    render(<VerdictFilter summary={{ counts, total: 2, findings: 9 }} />);

    expect(
      screen.getByRole("tab", { name: "Likely, 0 issues" }),
    ).toHaveAttribute("aria-selected", "true");
    await user.click(
      screen.getByRole("tab", { name: "Exploitable, 2 issues" }),
    );

    const params = lastPushedParams();
    expect(params.get("page")).toBe("1");
    expect(params.get("pageSize")).toBe("10");
    expect(params.get("filter[verdict]")).toBe("exploitable");
  });

  it("clears the verdict from the All tab, replacing a combined filter", async () => {
    const user = userEvent.setup();
    navigationState.searchParams = new URLSearchParams(
      "filter[verdict__in]=exploitable,likely",
    );
    render(<VerdictFilter summary={{ counts, total: 2, findings: 9 }} />);

    // The combined filter is a chip, not a tab.
    expect(
      screen
        .getAllByRole("tab")
        .every((tab) => tab.getAttribute("aria-selected") === "false"),
    ).toBe(true);
    expect(
      screen.getByRole("button", {
        name: "Remove Verdicts filter: Exploitable, Likely",
      }),
    ).toBeInTheDocument();

    await user.click(screen.getByRole("tab", { name: "All, 2 issues" }));

    expect(navigationState.push).toHaveBeenLastCalledWith("/issues", {
      scroll: false,
    });
  });

  it("shows the pattern filter and lets the user remove it", async () => {
    // Given
    const user = userEvent.setup();
    navigationState.searchParams = new URLSearchParams(
      "page=3&filter[pattern]=aws_public_bucket&filter[provider_id__in]=provider-1",
    );
    render(<VerdictFilter summary={{ counts, total: 2, findings: 9 }} />);
    // When
    await user.click(
      screen.getByRole("button", {
        name: "Remove Pattern filter: aws_public_bucket",
      }),
    );
    // Then
    const target = lastPushedParams();
    expect(target.has("filter[pattern]")).toBe(false);
    expect(target.get("filter[provider_id__in]")).toBe("provider-1");
    expect(target.get("page")).toBe("1");
  });
});
