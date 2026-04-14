import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { ProviderPageTabs } from "./provider-page-tabs";
import { getProviderTab, PROVIDER_TAB } from "./provider-page-tabs.shared";

const { pushMock } = vi.hoisted(() => ({
  pushMock: vi.fn(),
}));

vi.mock("next/navigation", () => ({
  useRouter: () => ({
    push: pushMock,
  }),
}));

describe("ProviderPageTabs", () => {
  beforeEach(() => {
    pushMock.mockClear();
  });

  it("falls back to accounts when tab search params are invalid", () => {
    expect(getProviderTab(undefined)).toBe(PROVIDER_TAB.ACCOUNTS);
    expect(getProviderTab(["account-groups"])).toBe(PROVIDER_TAB.ACCOUNTS);
    expect(getProviderTab("invalid-tab")).toBe(PROVIDER_TAB.ACCOUNTS);
    expect(getProviderTab(PROVIDER_TAB.ACCOUNT_GROUPS)).toBe(
      PROVIDER_TAB.ACCOUNT_GROUPS,
    );
  });

  it("shows the accounts tab when the route changes back to accounts", () => {
    const { rerender } = render(
      <ProviderPageTabs
        activeTab={PROVIDER_TAB.ACCOUNT_GROUPS}
        accountsContent={<div>Accounts content</div>}
        accountGroupsContent={<div>Account groups content</div>}
      />,
    );

    expect(screen.getByRole("tab", { name: "Account Groups" })).toHaveAttribute(
      "data-state",
      "active",
    );

    rerender(
      <ProviderPageTabs
        activeTab={PROVIDER_TAB.ACCOUNTS}
        accountsContent={<div>Accounts content</div>}
        accountGroupsContent={<div>Account groups content</div>}
      />,
    );

    expect(screen.getByRole("tab", { name: "Accounts" })).toHaveAttribute(
      "data-state",
      "active",
    );
    expect(screen.getByText("Accounts content")).toBeVisible();
  });

  it("does not switch the active tab before navigation updates the route", async () => {
    const user = userEvent.setup();

    render(
      <ProviderPageTabs
        activeTab={PROVIDER_TAB.ACCOUNTS}
        accountsContent={<div>Accounts content</div>}
        accountGroupsContent={<div>Account groups content</div>}
      />,
    );

    await user.click(screen.getByRole("tab", { name: "Account Groups" }));

    expect(pushMock).toHaveBeenCalledWith("/providers?tab=account-groups");
    expect(screen.getByRole("tab", { name: "Accounts" })).toHaveAttribute(
      "data-state",
      "active",
    );
    expect(
      screen.getByRole("tab", { name: "Account Groups" }),
    ).not.toHaveAttribute("data-state", "active");
  });
});
