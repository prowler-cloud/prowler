import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeAll, beforeEach, describe, expect, it, vi } from "vitest";

import { CrossProviderFilters } from "./cross-provider-filters";

// Radix/cmdk rely on pointer-capture and scrollIntoView, which jsdom does
// not implement. Polyfill them so the dropdown can open in tests.
beforeAll(() => {
  Object.defineProperty(HTMLElement.prototype, "hasPointerCapture", {
    configurable: true,
    value: vi.fn(() => false),
  });
  Object.defineProperty(HTMLElement.prototype, "setPointerCapture", {
    configurable: true,
    value: vi.fn(),
  });
  Object.defineProperty(HTMLElement.prototype, "releasePointerCapture", {
    configurable: true,
    value: vi.fn(),
  });
  Object.defineProperty(HTMLElement.prototype, "scrollIntoView", {
    configurable: true,
    value: vi.fn(),
  });
});

const { updateFilterMock } = vi.hoisted(() => ({
  updateFilterMock: vi.fn(),
}));

vi.mock("@/hooks/use-url-filters", () => ({
  useUrlFilters: () => ({ updateFilter: updateFilterMock, isPending: false }),
}));

vi.mock("next/navigation", () => ({
  useRouter: () => ({ push: vi.fn() }),
  usePathname: () => "/compliance",
  useSearchParams: () => new URLSearchParams(),
}));

const props = {
  providerTypes: ["aws", "azure"] as const,
  providerAccounts: [
    { id: "prov-1", label: "production (123456789012)", type: "aws" as const },
  ],
  providerGroups: [{ id: "group-1", name: "Platform" }],
  regions: ["eu-west-1", "us-east-1"],
};

describe("CrossProviderFilters", () => {
  beforeEach(() => {
    updateFilterMock.mockClear();
  });

  it("renders one filter per dimension", () => {
    render(<CrossProviderFilters {...props} />);

    expect(screen.getByText("All Providers")).toBeInTheDocument();
    expect(screen.getByText("All Accounts")).toBeInTheDocument();
    expect(screen.getByText("All Groups")).toBeInTheDocument();
    expect(screen.getByText("All Regions")).toBeInTheDocument();
  });

  it("hides the regions filter when no options exist", () => {
    render(<CrossProviderFilters {...props} regions={[]} />);

    expect(screen.queryByText("All Regions")).not.toBeInTheDocument();
  });

  it("pushes provider type selections into the URL filter", async () => {
    const user = userEvent.setup();
    render(<CrossProviderFilters {...props} />);

    await user.click(screen.getByText("All Providers"));
    await user.click(screen.getByRole("option", { name: "AWS" }));

    expect(updateFilterMock).toHaveBeenCalledWith("provider_type__in", ["aws"]);
  });
});
