import { Row } from "@tanstack/react-table";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";

vi.mock("next/navigation", () => ({
  useRouter: () => ({ push: vi.fn() }),
}));

vi.mock("../forms", () => ({
  DeleteForm: () => <div data-testid="delete-form" />,
  EditForm: () => <div data-testid="edit-form" />,
}));

import { InvitationProps } from "@/types";

import { DataTableRowActions } from "./data-table-row-actions";

const createRow = (state: string) =>
  ({
    original: {
      id: "invitation-1",
      attributes: { email: "jane@example.com", state },
      relationships: { inviter: { data: { type: "users", id: "user-1" } } },
    },
  }) as unknown as Row<InvitationProps>;

const openMenu = async (user: ReturnType<typeof userEvent.setup>) => {
  await user.click(screen.getByRole("button", { name: "Open actions menu" }));
};

const getMenuItem = (label: string) =>
  screen.getByText(label).closest("[role='menuitem']");

describe("DataTableRowActions (invitations)", () => {
  it("enables Edit and Revoke for a pending invitation", async () => {
    const user = userEvent.setup();
    render(<DataTableRowActions row={createRow("pending")} />);

    await openMenu(user);

    expect(getMenuItem("Edit Invitation")).not.toHaveAttribute("data-disabled");
    expect(getMenuItem("Revoke Invitation")).not.toHaveAttribute(
      "data-disabled",
    );
  });

  it.each(["accepted", "expired", "revoked"])(
    "disables Edit and Revoke for a %s invitation",
    async (state) => {
      const user = userEvent.setup();
      render(<DataTableRowActions row={createRow(state)} />);

      await openMenu(user);

      expect(getMenuItem("Edit Invitation")).toHaveAttribute("data-disabled");
      expect(getMenuItem("Revoke Invitation")).toHaveAttribute("data-disabled");
    },
  );
});
