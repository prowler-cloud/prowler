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

const hrefOf = (name: RegExp) =>
  screen.getByRole("link", { name }).getAttribute("href");

describe("VerdictFilter", () => {
  it("drops the page when a verdict is set or cleared, keeping other params", () => {
    navigationState.searchParams = new URLSearchParams(
      "page=3&pageSize=10&filter[verdict]=likely",
    );
    render(<VerdictFilter summary={{ counts, total: 2 }} />);

    const set = new URLSearchParams(hrefOf(/^exploitable 2$/i)!.split("?")[1]);
    expect(set.get("page")).toBeNull();
    expect(set.get("pageSize")).toBe("10");
    expect(set.get("filter[verdict]")).toBe("exploitable");

    const cleared = new URLSearchParams(hrefOf(/likely/i)!.split("?")[1]);
    expect(cleared.get("page")).toBeNull();
    expect(cleared.get("filter[verdict]")).toBeNull();
  });

  it("offers an All chip that clears the verdict and is active without one", () => {
    navigationState.searchParams = new URLSearchParams(
      "filter[verdict]=likely",
    );
    render(<VerdictFilter summary={{ counts, total: 2 }} />);

    expect(hrefOf(/^all 2$/i)).toBe("/issues");
  });
  it("shows the pattern filter and lets the user remove it", async () => {
    // Given
    const user = userEvent.setup();
    navigationState.searchParams = new URLSearchParams(
      "page=3&filter[pattern]=aws_public_bucket&filter[provider_id__in]=provider-1",
    );
    render(<VerdictFilter summary={{ counts, total: 2 }} />);
    // When
    await user.click(
      screen.getByRole("button", {
        name: "Remove Pattern filter: aws_public_bucket",
      }),
    );
    // Then
    const target = new URL(
      navigationState.push.mock.calls.at(-1)![0],
      "http://localhost",
    );
    expect(target.searchParams.has("filter[pattern]")).toBe(false);
    expect(target.searchParams.get("filter[provider_id__in]")).toBe(
      "provider-1",
    );
    expect(target.searchParams.get("page")).toBe("1");
  });
});
