import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";

import { ActionDropdown, ActionDropdownItem } from "./action-dropdown";

describe("ActionDropdownItem", () => {
  it("should keep a disabled item with tooltip dimmed, inert and hoverable", async () => {
    // Given
    const user = userEvent.setup();
    const onSelect = vi.fn();
    render(
      <ActionDropdown trigger={<button type="button">Actions</button>}>
        <ActionDropdownItem
          label="Compliance Impact"
          disabled
          disabledTooltip="Coming soon"
          onSelect={onSelect}
        />
      </ActionDropdown>,
    );

    // When
    await user.click(screen.getByRole("button", { name: "Actions" }));
    const item = screen.getByRole("menuitem", { name: /Compliance Impact/ });

    // Then — stays interactive for the tooltip but reads and looks disabled.
    expect(item).toHaveAttribute("aria-disabled", "true");
    expect(item).toHaveClass("opacity-50");

    // When
    await user.hover(item);

    // Then
    expect(await screen.findByRole("tooltip")).toHaveTextContent("Coming soon");

    // When
    await user.click(item);

    // Then
    expect(onSelect).not.toHaveBeenCalled();
  });

  it("should support controlled open state", async () => {
    // Given
    const user = userEvent.setup();
    const onOpenChange = vi.fn();
    const { rerender } = render(
      <ActionDropdown
        open={false}
        onOpenChange={onOpenChange}
        trigger={<button type="button">Actions</button>}
      >
        <ActionDropdownItem label="Item" />
      </ActionDropdown>,
    );

    // Then — closed until the controller says otherwise.
    expect(screen.queryByRole("menuitem")).not.toBeInTheDocument();

    // When
    await user.click(screen.getByRole("button", { name: "Actions" }));

    // Then — the component only notifies; the owner flips the prop.
    expect(onOpenChange).toHaveBeenCalledWith(true);
    expect(screen.queryByRole("menuitem")).not.toBeInTheDocument();

    // When
    rerender(
      <ActionDropdown
        open
        onOpenChange={onOpenChange}
        trigger={<button type="button">Actions</button>}
      >
        <ActionDropdownItem label="Item" />
      </ActionDropdown>,
    );

    // Then
    expect(screen.getByRole("menuitem", { name: "Item" })).toBeInTheDocument();
  });

  it("should stay open when the scroll happens inside the menu content", async () => {
    // Given
    const user = userEvent.setup();
    render(
      <ActionDropdown trigger={<button type="button">Actions</button>}>
        <ActionDropdownItem label="Item" />
      </ActionDropdown>,
    );
    await user.click(screen.getByRole("button", { name: "Actions" }));
    const item = screen.getByRole("menuitem", { name: "Item" });

    // When — a scroll event bubbling from inside the menu's own content.
    item.dispatchEvent(new Event("scroll", { bubbles: true }));

    // Then
    expect(screen.getByRole("menuitem", { name: "Item" })).toBeInTheDocument();

    // When — a scroll anywhere else (ancestor/page) still closes it.
    document.body.dispatchEvent(new Event("scroll", { bubbles: true }));

    // Then
    await vi.waitFor(() =>
      expect(screen.queryByRole("menuitem")).not.toBeInTheDocument(),
    );
  });

  it("should not dim an enabled item and fire its onSelect", async () => {
    // Given
    const user = userEvent.setup();
    const onSelect = vi.fn();
    render(
      <ActionDropdown trigger={<button type="button">Actions</button>}>
        <ActionDropdownItem label="Contextual Fix" onSelect={onSelect} />
      </ActionDropdown>,
    );

    // When
    await user.click(screen.getByRole("button", { name: "Actions" }));
    const item = screen.getByRole("menuitem", { name: /Contextual Fix/ });

    // Then
    expect(item).not.toHaveClass("opacity-50");

    // When
    await user.click(item);

    // Then
    expect(onSelect).toHaveBeenCalledOnce();
  });
});
