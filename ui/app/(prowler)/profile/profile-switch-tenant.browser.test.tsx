import { describe, vi } from "vitest";
import { render } from "vitest-browser-react";

import { MembershipsCard } from "@/components/users/profile/memberships-card";
import { expect, test } from "@/testing/test-extend";

import { ProfileSwitchTenantHarness } from "./profile-switch-tenant.harness";

vi.mock("next-auth/react", () => ({
  useSession: () => ({ update: vi.fn() }),
}));

vi.mock("@/auth.config", () => ({
  auth: vi.fn(),
}));

vi.mock("@/components/ui", () => ({
  useToast: () => ({ toast: vi.fn() }),
}));

vi.mock("@/actions/users/tenants", () => ({
  switchTenant: vi.fn(),
  updateTenantName: vi.fn(),
  createTenant: vi.fn(),
  deleteTenant: vi.fn(),
}));

// Test data: two orgs, one active
const ACTIVE_TENANT_ID = "tenant-active";
const OTHER_TENANT_ID = "tenant-other";

const memberships = [
  {
    id: "mem-1",
    type: "memberships" as const,
    attributes: { role: "owner", date_joined: "2025-05-19T11:31:00Z" },
    relationships: {
      tenant: { data: { type: "tenants", id: ACTIVE_TENANT_ID } },
      user: { data: { type: "users", id: "user-1" } },
    },
  },
  {
    id: "mem-2",
    type: "memberships" as const,
    attributes: { role: "member", date_joined: "2026-01-03T09:00:00Z" },
    relationships: {
      tenant: { data: { type: "tenants", id: OTHER_TENANT_ID } },
      user: { data: { type: "users", id: "user-1" } },
    },
  },
];

const tenantsMap = {
  [ACTIVE_TENANT_ID]: {
    type: "tenants",
    id: ACTIVE_TENANT_ID,
    attributes: { name: "My Active Org" },
    relationships: { memberships: { meta: { count: 1 }, data: [] } },
  },
  [OTHER_TENANT_ID]: {
    type: "tenants",
    id: OTHER_TENANT_ID,
    attributes: { name: "Another Org" },
    relationships: { memberships: { meta: { count: 1 }, data: [] } },
  },
};

function renderProfileOrganizations() {
  return render(
    <MembershipsCard
      memberships={memberships}
      tenantsMap={tenantsMap}
      isOwner={true}
      hasManageAccount={true}
      sessionTenantId={ACTIVE_TENANT_ID}
    />,
  );
}

// Browser tests: verify real DOM interactions in Chromium via harness pattern.
// Happy/error paths (form submit → session update) are covered by jsdom tests,
// as useActionState + vi.fn() mocks don't integrate with React 19's form action
// mechanism in browser mode.
describe("Profile page — Organization switch", () => {
  test("shows Active badge on current org and Switch button on other orgs", async () => {
    const h = new ProfileSwitchTenantHarness();
    renderProfileOrganizations();

    await expect.element(h.activeBadge()).toBeVisible();
    await expect.element(h.switchButtons().first()).toBeVisible();
    await expect.element(h.orgName("My Active Org")).toBeVisible();
    await expect.element(h.orgName("Another Org")).toBeVisible();
  });

  test("opens confirmation dialog when clicking Switch", async () => {
    const h = new ProfileSwitchTenantHarness();
    renderProfileOrganizations();

    await h.clickSwitchOnFirstAvailable();

    await expect.element(h.confirmationDialog()).toBeVisible();
    await expect.element(h.confirmationTitle()).toBeVisible();
    await expect.element(h.confirmButton()).toBeVisible();
    await expect.element(h.cancelButton()).toBeVisible();
  });

  test("closes dialog without switching when clicking Cancel", async () => {
    const h = new ProfileSwitchTenantHarness();
    renderProfileOrganizations();

    await h.clickSwitchOnFirstAvailable();
    await expect.element(h.confirmationDialog()).toBeVisible();

    await h.cancelSwitch();

    await expect.element(h.confirmationDialog()).not.toBeInTheDocument();
    await expect.element(h.switchButtons().first()).toBeVisible();
  });
});
