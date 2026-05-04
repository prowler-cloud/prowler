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

  it("falls back to providers when tab search params are invalid", () => {
    expect(getProviderTab(undefined)).toBe(PROVIDER_TAB.PROVIDERS);
    expect(getProviderTab(["provider-groups"])).toBe(PROVIDER_TAB.PROVIDERS);
    expect(getProviderTab("invalid-tab")).toBe(PROVIDER_TAB.PROVIDERS);
    expect(getProviderTab(PROVIDER_TAB.PROVIDER_GROUPS)).toBe(
      PROVIDER_TAB.PROVIDER_GROUPS,
    );
  });

  it("shows the providers tab when the route changes back to providers", () => {
    const { rerender } = render(
      <ProviderPageTabs
        activeTab={PROVIDER_TAB.PROVIDER_GROUPS}
        accountsContent={<div>Providers content</div>}
        accountGroupsContent={<div>Provider groups content</div>}
      />,
    );

    expect(
      screen.getByRole("tab", { name: "Provider Groups" }),
    ).toHaveAttribute("data-state", "active");

    rerender(
      <ProviderPageTabs
        activeTab={PROVIDER_TAB.PROVIDERS}
        accountsContent={<div>Providers content</div>}
        accountGroupsContent={<div>Provider groups content</div>}
      />,
    );

    expect(screen.getByRole("tab", { name: "Providers" })).toHaveAttribute(
      "data-state",
      "active",
    );
    expect(screen.getByText("Providers content")).toBeVisible();
  });

  it("does not switch the active tab before navigation updates the route", async () => {
    const user = userEvent.setup();

    render(
      <ProviderPageTabs
        activeTab={PROVIDER_TAB.PROVIDERS}
        accountsContent={<div>Providers content</div>}
        accountGroupsContent={<div>Provider groups content</div>}
      />,
    );

    await user.click(screen.getByRole("tab", { name: "Provider Groups" }));

    expect(pushMock).toHaveBeenCalledWith("/providers?tab=provider-groups");
    expect(screen.getByRole("tab", { name: "Providers" })).toHaveAttribute(
      "data-state",
      "active",
    );
    expect(
      screen.getByRole("tab", { name: "Provider Groups" }),
    ).not.toHaveAttribute("data-state", "active");
  });
});
