"use client";

import { Row } from "@tanstack/react-table";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";

import { PROVIDERS_ROW_TYPE } from "@/types/providers-table";

const checkConnectionProviderMock = vi.hoisted(() => vi.fn());

vi.mock("@/actions/providers/providers", () => ({
  checkConnectionProvider: checkConnectionProviderMock,
}));

vi.mock("@/components/providers/wizard", () => ({
  ProviderWizardModal: () => null,
}));

vi.mock("../forms", () => ({
  EditForm: () => null,
}));

vi.mock("../forms/delete-form", () => ({
  DeleteForm: () => null,
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

describe("DataTableRowActions", () => {
  it("renders the exact phase 1 menu actions for provider rows", async () => {
    // Given
    const user = userEvent.setup();
    render(<DataTableRowActions row={createRow()} />);

    // When
    await user.click(screen.getByRole("button"));

    // Then
    expect(screen.getByText("Edit Provider Alias")).toBeInTheDocument();
    expect(screen.getByText("Update Credentials")).toBeInTheDocument();
    expect(screen.getByText("Test Connection")).toBeInTheDocument();
    expect(screen.getByText("Delete Provider")).toBeInTheDocument();
    expect(screen.queryByText("Add Credentials")).not.toBeInTheDocument();
  });
});
