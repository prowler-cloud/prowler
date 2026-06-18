import { Row } from "@tanstack/react-table";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";

// The forms pull in server actions (`@/actions/users/users`) that can't run in
// jsdom, so stub them with identifiable markers to assert which modal opens.
vi.mock("../forms", () => ({
  DeleteForm: ({ userId }: { userId: string }) => (
    <div data-testid="delete-form">delete-form:{userId}</div>
  ),
  EditForm: ({ userId }: { userId: string }) => (
    <div data-testid="edit-form">edit-form:{userId}</div>
  ),
  ExpelUserForm: ({ userId }: { userId: string }) => (
    <div data-testid="expel-form">expel-form:{userId}</div>
  ),
}));

import { DataTableRowActions } from "./data-table-row-actions";

interface RowOptions {
  id?: string;
  isCurrentUser?: boolean;
  canBeExpelled?: boolean;
  currentTenantId?: string;
}

const createRow = ({
  id = "user-1",
  isCurrentUser,
  canBeExpelled,
  currentTenantId,
}: RowOptions = {}) =>
  ({
    original: {
      id,
      attributes: {
        name: "Jane Doe",
        email: "jane@example.com",
        company_name: "Acme",
        role: { name: "admin" },
      },
      isCurrentUser,
      canBeExpelled,
      currentTenantId,
    },
  }) as unknown as Row<{ id: string }>;

const openMenu = async (user: ReturnType<typeof userEvent.setup>) => {
  await user.click(screen.getByRole("button", { name: "Open actions menu" }));
};

describe("DataTableRowActions (users)", () => {
  it("always renders the Edit User action", async () => {
    const user = userEvent.setup();
    render(<DataTableRowActions row={createRow()} />);

    await openMenu(user);

    expect(screen.getByText("Edit User")).toBeInTheDocument();
  });

  it("shows Delete User only for the current user's row", async () => {
    const user = userEvent.setup();
    render(<DataTableRowActions row={createRow({ isCurrentUser: true })} />);

    await openMenu(user);

    expect(screen.getByText("Delete User")).toBeInTheDocument();
    expect(screen.getByText("Danger zone")).toBeInTheDocument();
  });

  it("does NOT show Delete User for another user's row", async () => {
    const user = userEvent.setup();
    render(<DataTableRowActions row={createRow({ isCurrentUser: false })} />);

    await openMenu(user);

    expect(screen.queryByText("Delete User")).not.toBeInTheDocument();
  });

  it("does NOT show Delete User when isCurrentUser is undefined", async () => {
    const user = userEvent.setup();
    render(<DataTableRowActions row={createRow({})} />);

    await openMenu(user);

    expect(screen.queryByText("Delete User")).not.toBeInTheDocument();
  });

  it("hides the Danger zone entirely when the user can neither be deleted nor expelled", async () => {
    const user = userEvent.setup();
    render(
      <DataTableRowActions
        row={createRow({ isCurrentUser: false, canBeExpelled: false })}
      />,
    );

    await openMenu(user);

    // Only the non-destructive Edit action remains.
    expect(screen.getByText("Edit User")).toBeInTheDocument();
    expect(screen.queryByText("Danger zone")).not.toBeInTheDocument();
    expect(screen.queryByText("Delete User")).not.toBeInTheDocument();
    expect(
      screen.queryByText("Expel from organization"),
    ).not.toBeInTheDocument();
  });

  it("shows Expel but not Delete User for an expellable, non-current user", async () => {
    const user = userEvent.setup();
    render(
      <DataTableRowActions
        row={createRow({
          isCurrentUser: false,
          canBeExpelled: true,
          currentTenantId: "tenant-1",
        })}
      />,
    );

    await openMenu(user);

    expect(screen.getByText("Danger zone")).toBeInTheDocument();
    expect(screen.getByText("Expel from organization")).toBeInTheDocument();
    expect(screen.queryByText("Delete User")).not.toBeInTheDocument();
  });

  it("renders Delete User with destructive styling", async () => {
    const user = userEvent.setup();
    render(<DataTableRowActions row={createRow({ isCurrentUser: true })} />);

    await openMenu(user);

    const menuItem = screen
      .getByText("Delete User")
      .closest("[role='menuitem']");
    expect(menuItem).toBeInTheDocument();
    expect(menuItem).toHaveClass("text-text-error-primary");
  });

  it("opens the delete confirmation modal when Delete User is selected", async () => {
    const user = userEvent.setup();
    render(
      <DataTableRowActions
        row={createRow({ id: "user-42", isCurrentUser: true })}
      />,
    );

    await openMenu(user);
    await user.click(screen.getByText("Delete User"));

    expect(screen.getByText("Are you absolutely sure?")).toBeInTheDocument();
    expect(screen.getByTestId("delete-form")).toHaveTextContent(
      "delete-form:user-42",
    );
  });
});
