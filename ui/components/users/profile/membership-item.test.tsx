import { render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";

import { MembershipItem } from "./membership-item";

vi.mock("next-auth/react", () => ({
  useSession: () => ({ update: vi.fn() }),
}));

vi.mock("@/auth.config", () => ({
  auth: vi.fn(),
}));

vi.mock("@/actions/users/tenants", () => ({
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

describe("MembershipItem", () => {
  it("shows Switch button when not active tenant", () => {
    render(
      <MembershipItem
        membership={baseMembership}
        tenantName="Test Org"
        tenantId="tenant-1"
        isOwner={false}
        sessionTenantId="different-tenant"
        availableTenants={[]}
        membershipCount={1}
      />,
    );

    expect(screen.getByRole("button", { name: /switch/i })).toBeInTheDocument();
    expect(screen.queryByText("Active")).not.toBeInTheDocument();
  });

  it("shows Active badge when active tenant", () => {
    render(
      <MembershipItem
        membership={baseMembership}
        tenantName="Test Org"
        tenantId="tenant-1"
        isOwner={false}
        sessionTenantId="tenant-1"
        availableTenants={[]}
        membershipCount={1}
      />,
    );

    expect(screen.getByText("Active")).toBeInTheDocument();
    expect(
      screen.queryByRole("button", { name: /switch/i }),
    ).not.toBeInTheDocument();
  });

  it("shows Edit button when user is owner", () => {
    render(
      <MembershipItem
        membership={baseMembership}
        tenantName="Test Org"
        tenantId="tenant-1"
        isOwner={true}
        sessionTenantId="tenant-1"
        availableTenants={[]}
        membershipCount={1}
      />,
    );

    expect(screen.getByRole("button", { name: /edit/i })).toBeInTheDocument();
  });

  it("hides Edit button when user is not owner", () => {
    render(
      <MembershipItem
        membership={baseMembership}
        tenantName="Test Org"
        tenantId="tenant-1"
        isOwner={false}
        sessionTenantId="tenant-1"
        availableTenants={[]}
        membershipCount={1}
      />,
    );

    expect(
      screen.queryByRole("button", { name: /edit/i }),
    ).not.toBeInTheDocument();
  });

  it("displays membership role as badge", () => {
    render(
      <MembershipItem
        membership={baseMembership}
        tenantName="Test Org"
        tenantId="tenant-1"
        isOwner={false}
        sessionTenantId="tenant-1"
        availableTenants={[]}
        membershipCount={1}
      />,
    );

    expect(screen.getByText("owner")).toBeInTheDocument();
  });

  it("shows Delete button when isOwner and membershipCount > 1", () => {
    render(
      <MembershipItem
        membership={baseMembership}
        tenantName="Test Org"
        tenantId="tenant-1"
        isOwner={true}
        sessionTenantId="tenant-1"
        availableTenants={[{ id: "tenant-2", name: "Other Org" }]}
        membershipCount={2}
      />,
    );
    expect(
      screen.getByRole("button", { name: /delete/i }),
    ).toBeInTheDocument();
  });

  it("hides Delete button when membershipCount === 1", () => {
    render(
      <MembershipItem
        membership={baseMembership}
        tenantName="Test Org"
        tenantId="tenant-1"
        isOwner={true}
        sessionTenantId="tenant-1"
        availableTenants={[]}
        membershipCount={1}
      />,
    );
    expect(
      screen.queryByRole("button", { name: /delete/i }),
    ).not.toBeInTheDocument();
  });

  it("hides Delete button when not isOwner", () => {
    render(
      <MembershipItem
        membership={baseMembership}
        tenantName="Test Org"
        tenantId="tenant-1"
        isOwner={false}
        sessionTenantId="tenant-1"
        availableTenants={[{ id: "tenant-2", name: "Other Org" }]}
        membershipCount={2}
      />,
    );
    expect(
      screen.queryByRole("button", { name: /delete/i }),
    ).not.toBeInTheDocument();
  });
});
