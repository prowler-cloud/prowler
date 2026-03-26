import { describe, vi } from "vitest";
import { render } from "vitest-browser-react";

import { expect, test } from "@/testing/test-extend";

import { MembershipItem } from "./membership-item";
import { MembershipsCardClient } from "./memberships-card-client";
import { OrganizationManagementHarness } from "./organization-management.harness";

// Mocks
vi.mock("next-auth/react", () => ({
  useSession: () => ({ update: vi.fn() }),
}));

vi.mock("@/auth.config", () => ({
  auth: vi.fn(),
}));

vi.mock("@/actions/users/tenants", () => ({
  createTenant: vi.fn(),
  switchTenant: vi.fn(),
  updateTenantName: vi.fn(),
  deleteTenant: vi.fn(),
}));

vi.mock("@/components/ui", () => ({
  useToast: () => ({ toast: vi.fn() }),
}));

const baseMembership = {
  id: "mem-1",
  type: "memberships" as const,
  attributes: { role: "owner", date_joined: "2025-05-19T11:31:00Z" },
  relationships: {
    tenant: { data: { type: "tenants", id: "tenant-1" } },
    user: { data: { type: "users", id: "user-1" } },
  },
};

const tenantsMap = {
  "tenant-1": {
    id: "tenant-1",
    type: "tenants" as const,
    attributes: { name: "My Org" },
    relationships: { memberships: { meta: { count: 1 }, data: [] } },
  },
  "tenant-2": {
    id: "tenant-2",
    type: "tenants" as const,
    attributes: { name: "Other Org" },
    relationships: { memberships: { meta: { count: 1 }, data: [] } },
  },
};

describe("Organization Management (browser)", () => {
  describe("Create flow", () => {
    test("shows Create button when hasManageAccount", async () => {
      const h = new OrganizationManagementHarness();
      render(
        <MembershipsCardClient
          memberships={[baseMembership]}
          tenantsMap={tenantsMap}
          isOwner={true}
          hasManageAccount={true}
          sessionTenantId="tenant-1"
        />,
      );
      await expect.element(h.createButton()).toBeVisible();
    });

    test("hides Create button when not hasManageAccount", async () => {
      const h = new OrganizationManagementHarness();
      render(
        <MembershipsCardClient
          memberships={[baseMembership]}
          tenantsMap={tenantsMap}
          isOwner={false}
          hasManageAccount={false}
          sessionTenantId="tenant-1"
        />,
      );
      await expect.element(h.createButton()).not.toBeInTheDocument();
    });

    test("opens create modal on button click", async () => {
      const h = new OrganizationManagementHarness();
      render(
        <MembershipsCardClient
          memberships={[baseMembership]}
          tenantsMap={tenantsMap}
          isOwner={true}
          hasManageAccount={true}
          sessionTenantId="tenant-1"
        />,
      );
      await h.openCreateModal();
      await expect.element(h.dialog()).toBeVisible();
    });
  });

  describe("Delete flow", () => {
    test("shows Delete button for owner with multiple tenants", async () => {
      const h = new OrganizationManagementHarness();
      render(
        <MembershipItem
          membership={baseMembership}
          tenantName="My Org"
          tenantId="tenant-1"
          isOwner={true}
          sessionTenantId="tenant-2"
          availableTenants={[{ id: "tenant-2", name: "Other Org" }]}
          membershipCount={2}
        />,
      );
      await expect.element(h.deleteButton()).toBeVisible();
    });

    test("hides Delete button for single tenant", async () => {
      const h = new OrganizationManagementHarness();
      render(
        <MembershipItem
          membership={baseMembership}
          tenantName="My Org"
          tenantId="tenant-1"
          isOwner={true}
          sessionTenantId="tenant-1"
          availableTenants={[]}
          membershipCount={1}
        />,
      );
      await expect.element(h.deleteButton()).not.toBeInTheDocument();
    });

    test("opens delete modal and requires name confirmation", async () => {
      const h = new OrganizationManagementHarness();
      render(
        <MembershipItem
          membership={baseMembership}
          tenantName="My Org"
          tenantId="tenant-1"
          isOwner={true}
          sessionTenantId="tenant-2"
          availableTenants={[{ id: "tenant-2", name: "Other Org" }]}
          membershipCount={2}
        />,
      );
      await h.openDeleteModal();
      await expect.element(h.modal()).toBeVisible();

      // Submit should be disabled until name matches
      await expect.element(h.submitButton(/delete/i)).toBeDisabled();

      await h.fillConfirmation("My Org");
      await expect.element(h.submitButton(/delete/i)).toBeEnabled();
    });
  });
});
