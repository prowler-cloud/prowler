import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";

import { ScansProvidersEmptyState } from "./scans-providers-empty-state";

const { replaceMock, searchParamsValue } = vi.hoisted(() => ({
  replaceMock: vi.fn(),
  searchParamsValue: { current: "" },
}));

vi.mock("next/navigation", () => ({
  usePathname: () => "/scans",
  useRouter: () => ({
    replace: replaceMock,
  }),
  useSearchParams: () => new URLSearchParams(searchParamsValue.current),
}));

vi.mock("@/components/providers/wizard", () => ({
  ProviderWizardModal: ({ open }: { open: boolean }) =>
    open ? <div role="dialog">Provider wizard</div> : null,
}));

vi.mock("./no-providers-connected", () => ({
  NoProvidersConnected: () => <div>No Connected Providers</div>,
}));

describe("ScansProvidersEmptyState", () => {
  afterEach(() => {
    vi.clearAllMocks();
    searchParamsValue.current = "";
  });

  it("shows the add provider message and opens the provider wizard", async () => {
    const user = userEvent.setup();

    render(<ScansProvidersEmptyState thereIsNoProviders />);

    expect(screen.getByText("No Providers Configured")).toBeInTheDocument();

    await user.click(
      screen.getByRole("button", { name: /open add provider modal/i }),
    );

    expect(screen.getByRole("dialog")).toHaveTextContent("Provider wizard");
  });

  it("clears the launch scan URL intent before opening the provider wizard", async () => {
    // Given
    searchParamsValue.current = "tab=completed&launchScan=true";
    const user = userEvent.setup();

    render(<ScansProvidersEmptyState thereIsNoProviders />);

    // When
    await user.click(
      screen.getByRole("button", { name: /open add provider modal/i }),
    );

    // Then
    expect(replaceMock).toHaveBeenCalledWith("/scans?tab=completed", {
      scroll: false,
    });
    expect(screen.getByRole("dialog")).toHaveTextContent("Provider wizard");
  });

  it("shows the no connected providers message", () => {
    render(<ScansProvidersEmptyState thereIsNoProviders={false} />);

    expect(screen.getByText("No Connected Providers")).toBeInTheDocument();
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
  });
});
