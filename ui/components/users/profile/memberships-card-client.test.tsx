import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";

import type { MembershipDetailData, TenantDetailData } from "@/types/users";

import { MembershipsCardClient } from "./memberships-card-client";

vi.mock("next/navigation", () => ({
  usePathname: () => "/profile",
  useRouter: () => ({
    push: vi.fn(),
  }),
  useSearchParams: () => new URLSearchParams(),
}));

vi.mock("@/contexts", () => ({
  useFilterTransitionOptional: () => null,
}));

vi.mock("@/lib", () => ({
  getPaginationInfo: () => ({
    currentPage: 1,
    totalPages: 1,
    totalEntries: 1,
    itemsPerPageOptions: [10, 20, 50],
  }),
}));

vi.mock("@/components/users/forms/create-tenant-form", () => ({
  CreateTenantForm: () => <div>Create organization form</div>,
}));

vi.mock("@/components/users/forms", () => ({
  EditTenantForm: () => <div>Edit organization form</div>,
}));

vi.mock("@/components/users/forms/delete-tenant-form", () => ({
  DeleteTenantForm: () => <div>Delete organization form</div>,
}));

vi.mock("@/components/users/forms/switch-tenant-form", () => ({
  SwitchTenantForm: () => <div>Switch organization form</div>,
}));

vi.mock("@/components/shadcn", async (importOriginal) => ({
  ...(await importOriginal<Record<string, unknown>>()),
  useToast: () => ({ toast: vi.fn() }),
}));

const memberships = [
  {
    id: "membership-1",
    type: "memberships",
    attributes: {
      role: "owner",
      date_joined: "2026-06-09T10:00:00Z",
    },
    relationships: {
      tenant: {
        data: {
          type: "tenants",
          id: "tenant-1",
        },
      },
    },
  },
] satisfies MembershipDetailData[];

const tenantsMap = {
  "tenant-1": {
    id: "tenant-1",
    type: "tenants",
    attributes: {
      name: "Prowler Labs",
    },
    relationships: {
      memberships: {
        meta: {
          count: 1,
        },
        data: [],
      },
    },
  },
} satisfies Record<string, TenantDetailData>;

describe("MembershipsCardClient", () => {
  it("renders organizations in a table with the active status before the name", () => {
    // When
    render(
      <MembershipsCardClient
        memberships={memberships}
        tenantsMap={tenantsMap}
        hasManageAccount
        sessionTenantId="tenant-1"
      />,
    );

    // Then
    expect(screen.getByRole("table")).toBeInTheDocument();
    expect(
      screen.getByRole("columnheader", { name: "Role" }),
    ).toBeInTheDocument();
    expect(
      screen.getByRole("columnheader", { name: "Status" }),
    ).toBeInTheDocument();
    expect(
      screen.getByRole("columnheader", { name: "Name" }),
    ).toBeInTheDocument();

    const row = screen.getByRole("row", {
      name: /owner active prowler labs/i,
    });
    const cells = within(row).getAllByRole("cell");

    expect(cells[0]).toHaveTextContent("owner");
    expect(cells[1]).toHaveTextContent("Active");
    expect(cells[2]).toHaveTextContent("Prowler Labs");
  });

  it("keeps organization edit and delete actions inside the actions menu", async () => {
    // Given
    const user = userEvent.setup();

    render(
      <MembershipsCardClient
        memberships={memberships}
        tenantsMap={tenantsMap}
        hasManageAccount
        sessionTenantId="tenant-1"
      />,
    );

    // When
    expect(
      screen.queryByRole("button", { name: "Edit" }),
    ).not.toBeInTheDocument();
    expect(
      screen.queryByRole("button", { name: "Delete" }),
    ).not.toBeInTheDocument();

    await user.click(
      screen.getByRole("button", {
        name: "Open actions menu",
      }),
    );

    // Then
    expect(
      screen.getByRole("menuitem", { name: /edit organization/i }),
    ).toBeInTheDocument();
    expect(
      screen.getByRole("menuitem", { name: /delete organization/i }),
    ).toBeInTheDocument();
  });
});
