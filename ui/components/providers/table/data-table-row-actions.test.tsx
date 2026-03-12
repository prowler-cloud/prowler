import { Row } from "@tanstack/react-table";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";

import {
  PROVIDERS_GROUP_KIND,
  PROVIDERS_ROW_TYPE,
} from "@/types/providers-table";

const checkConnectionProviderMock = vi.hoisted(() => vi.fn());

vi.mock("@/actions/organizations/organizations", () => ({
  updateOrganizationName: vi.fn(),
}));

vi.mock("@/actions/providers/providers", () => ({
  checkConnectionProvider: checkConnectionProviderMock,
}));

vi.mock("@/components/providers/wizard", () => ({
  ProviderWizardModal: () => null,
}));

vi.mock("../forms/delete-form", () => ({
  DeleteForm: () => null,
}));

vi.mock("../forms/delete-organization-form", () => ({
  DeleteOrganizationForm: () => null,
}));

vi.mock("../forms/edit-name-form", () => ({
  EditNameForm: () => null,
}));

vi.mock("@/components/ui", () => ({
  useToast: () => ({ toast: vi.fn() }),
}));

vi.mock("@/lib/provider-helpers", () => ({
  testProviderConnection: vi.fn(),
}));

import { DataTableRowActions } from "./data-table-row-actions";

const createRow = () =>
  ({
    original: {
      id: "provider-1",
      rowType: PROVIDERS_ROW_TYPE.PROVIDER,
      type: "providers",
      attributes: {
        provider: "aws",
        uid: "111111111111",
        alias: "AWS App Account",
        status: "completed",
        resources: 0,
        connection: {
          connected: true,
          last_checked_at: "2025-02-13T11:17:00Z",
        },
        scanner_args: {
          only_logs: false,
          excluded_checks: [],
          aws_retries_max_attempts: 3,
        },
        inserted_at: "2025-02-13T11:17:00Z",
        updated_at: "2025-02-13T11:17:00Z",
        created_by: {
          object: "user",
          id: "user-1",
        },
      },
      relationships: {
        secret: {
          data: null,
        },
        provider_groups: {
          meta: {
            count: 0,
          },
          data: [],
        },
      },
      groupNames: [],
    },
  }) as Row<any>;

const createOrgRow = () =>
  ({
    original: {
      id: "org-1",
      rowType: PROVIDERS_ROW_TYPE.ORGANIZATION,
      groupKind: PROVIDERS_GROUP_KIND.ORGANIZATION,
      name: "My AWS Organization",
      externalId: "o-abc123def4",
      parentExternalId: null,
      organizationId: "org-1",
      providerCount: 3,
      subRows: [
        {
          id: "provider-child-1",
          rowType: PROVIDERS_ROW_TYPE.PROVIDER,
          type: "providers",
          attributes: { provider: "aws", uid: "111", alias: null },
          relationships: {
            secret: { data: { id: "secret-1", type: "secrets" } },
          },
        },
        {
          id: "provider-child-2",
          rowType: PROVIDERS_ROW_TYPE.PROVIDER,
          type: "providers",
          attributes: { provider: "aws", uid: "222", alias: null },
          relationships: { secret: { data: null } },
        },
      ],
    },
  }) as Row<any>;

const createOuRow = () =>
  ({
    original: {
      id: "ou-1",
      rowType: PROVIDERS_ROW_TYPE.ORGANIZATION,
      groupKind: PROVIDERS_GROUP_KIND.ORGANIZATION_UNIT,
      name: "Production OU",
      externalId: "ou-abc123",
      parentExternalId: "o-abc123def4",
      organizationId: "org-1",
      providerCount: 2,
      subRows: [
        {
          id: "provider-ou-child-1",
          rowType: PROVIDERS_ROW_TYPE.PROVIDER,
          type: "providers",
          attributes: { provider: "aws", uid: "333", alias: null },
          relationships: {
            secret: { data: { id: "secret-2", type: "secrets" } },
          },
        },
      ],
    },
  }) as Row<any>;

describe("DataTableRowActions", () => {
  it("renders the exact phase 1 menu actions for provider rows", async () => {
    // Given
    const user = userEvent.setup();
    render(
      <DataTableRowActions
        row={createRow()}
        hasSelection={false}
        isRowSelected={false}
        testableProviderIds={[]}
        onClearSelection={vi.fn()}
      />,
    );

    // When
    await user.click(screen.getByRole("button"));

    // Then
    expect(screen.getByText("Edit Provider Alias")).toBeInTheDocument();
    expect(screen.getByText("Update Credentials")).toBeInTheDocument();
    expect(screen.getByText("Test Connection")).toBeInTheDocument();
    expect(screen.getByText("Delete Provider")).toBeInTheDocument();
    expect(screen.queryByText("Add Credentials")).not.toBeInTheDocument();
  });

  it("renders all 4 organization actions for org rows", async () => {
    const user = userEvent.setup();
    render(
      <DataTableRowActions
        row={createOrgRow()}
        hasSelection={false}
        isRowSelected={false}
        testableProviderIds={[]}
        onClearSelection={vi.fn()}
      />,
    );

    await user.click(screen.getByRole("button"));

    expect(screen.getByText("Edit Organization Name")).toBeInTheDocument();
    expect(screen.getByText("Update Credentials")).toBeInTheDocument();
    // 1 of 2 child providers has a secret
    expect(screen.getByText("Test Connections (1)")).toBeInTheDocument();
    expect(screen.getByText("Delete Organization")).toBeInTheDocument();
  });

  it("renders Delete Organization with destructive styling for org rows", async () => {
    const user = userEvent.setup();
    render(
      <DataTableRowActions
        row={createOrgRow()}
        hasSelection={false}
        isRowSelected={false}
        testableProviderIds={[]}
        onClearSelection={vi.fn()}
      />,
    );

    await user.click(screen.getByRole("button"));

    const deleteItem = screen.getByText("Delete Organization");
    // Destructive items are rendered with error text color
    const menuItem = deleteItem.closest("[role='menuitem']");
    expect(menuItem).toBeInTheDocument();
    expect(menuItem).toHaveClass("text-text-error-primary");
  });

  it("renders only Test Connections and Delete for OU rows", async () => {
    const user = userEvent.setup();
    render(
      <DataTableRowActions
        row={createOuRow()}
        hasSelection={false}
        isRowSelected={false}
        testableProviderIds={[]}
        onClearSelection={vi.fn()}
      />,
    );

    await user.click(screen.getByRole("button"));

    expect(screen.getByText("Test Connections (1)")).toBeInTheDocument();
    expect(screen.getByText("Delete Organization Unit")).toBeInTheDocument();
  });

  it("shows selected provider count in Test Connections when org row has active selection", async () => {
    const user = userEvent.setup();
    render(
      <DataTableRowActions
        row={createOrgRow()}
        hasSelection={true}
        isRowSelected={false}
        testableProviderIds={["provider-child-1", "provider-standalone"]}
        onClearSelection={vi.fn()}
      />,
    );

    await user.click(screen.getByRole("button"));

    // Should show count of selected testable providers (2), not all org children (1)
    expect(screen.getByText("Test Connections (2)")).toBeInTheDocument();
    expect(screen.queryByText("Test Connections (1)")).not.toBeInTheDocument();
  });

  it("shows selected provider count in Test Connections when OU row has active selection", async () => {
    const user = userEvent.setup();
    render(
      <DataTableRowActions
        row={createOuRow()}
        hasSelection={true}
        isRowSelected={false}
        testableProviderIds={["provider-ou-child-1", "provider-standalone"]}
        onClearSelection={vi.fn()}
      />,
    );

    await user.click(screen.getByRole("button"));

    // Should show count of selected testable providers (2), not all OU children (1)
    expect(screen.getByText("Test Connections (2)")).toBeInTheDocument();
    expect(screen.queryByText("Test Connections (1)")).not.toBeInTheDocument();
  });

  it("does NOT render Edit Organization Name or Update Credentials for OU rows", async () => {
    const user = userEvent.setup();
    render(
      <DataTableRowActions
        row={createOuRow()}
        hasSelection={false}
        isRowSelected={false}
        testableProviderIds={[]}
        onClearSelection={vi.fn()}
      />,
    );

    await user.click(screen.getByRole("button"));

    expect(
      screen.queryByText("Edit Organization Name"),
    ).not.toBeInTheDocument();
    expect(screen.queryByText("Update Credentials")).not.toBeInTheDocument();
  });
});
