import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { useState } from "react";
import { describe, expect, it, vi } from "vitest";

import { Accordion, AccordionItemProps } from "./Accordion";

const buildItems = (): AccordionItemProps[] => [
  { key: "first", title: "First item", content: "First content" },
  { key: "second", title: "Second item", content: "Second content" },
];

describe("Accordion", () => {
  describe("when uncontrolled", () => {
    it("should expand an item when its trigger is clicked", async () => {
      // Given
      const user = userEvent.setup();
      render(<Accordion items={buildItems()} />);
      expect(screen.queryByText("First content")).not.toBeInTheDocument();

      // When
      await user.click(screen.getByRole("button", { name: "First item" }));

      // Then
      expect(screen.getByText("First content")).toBeVisible();
    });

    it("should collapse an expanded item when its trigger is clicked again", async () => {
      // Given
      const user = userEvent.setup();
      render(
        <Accordion items={buildItems()} defaultExpandedKeys={["first"]} />,
      );
      expect(screen.getByText("First content")).toBeVisible();

      // When
      await user.click(screen.getByRole("button", { name: "First item" }));

      // Then
      expect(screen.queryByText("First content")).not.toBeInTheDocument();
    });

    it("should collapse siblings in single selection mode", async () => {
      // Given
      const user = userEvent.setup();
      render(
        <Accordion
          items={buildItems()}
          selectionMode="single"
          defaultExpandedKeys={["first"]}
        />,
      );

      // When
      await user.click(screen.getByRole("button", { name: "Second item" }));

      // Then
      expect(screen.getByText("Second content")).toBeVisible();
      expect(screen.queryByText("First content")).not.toBeInTheDocument();
    });

    it("should keep siblings expanded in multiple selection mode", async () => {
      // Given
      const user = userEvent.setup();
      render(
        <Accordion
          items={buildItems()}
          selectionMode="multiple"
          defaultExpandedKeys={["first"]}
        />,
      );

      // When
      await user.click(screen.getByRole("button", { name: "Second item" }));

      // Then
      expect(screen.getByText("First content")).toBeVisible();
      expect(screen.getByText("Second content")).toBeVisible();
    });

    it("should not expand a disabled item", async () => {
      // Given
      const user = userEvent.setup();
      render(
        <Accordion
          items={[
            {
              key: "locked",
              title: "Locked item",
              content: "Locked content",
              isDisabled: true,
            },
          ]}
        />,
      );

      // When
      await user.click(screen.getByRole("button", { name: "Locked item" }));

      // Then
      expect(screen.queryByText("Locked content")).not.toBeInTheDocument();
    });
  });

  describe("when controlled", () => {
    it("should reflect the selectedKeys prop and report changes through onSelectionChange", async () => {
      // Given
      const user = userEvent.setup();
      const onSelectionChange = vi.fn();
      const ControlledAccordion = () => {
        const [keys, setKeys] = useState<string[]>([]);
        return (
          <Accordion
            items={buildItems()}
            selectionMode="multiple"
            selectedKeys={keys}
            onSelectionChange={(next) => {
              onSelectionChange(next);
              setKeys(next);
            }}
          />
        );
      };
      render(<ControlledAccordion />);

      // When
      await user.click(screen.getByRole("button", { name: "First item" }));

      // Then
      expect(onSelectionChange).toHaveBeenCalledWith(["first"]);
      expect(screen.getByText("First content")).toBeVisible();

      // When the item is toggled off
      await user.click(screen.getByRole("button", { name: "First item" }));

      // Then
      expect(onSelectionChange).toHaveBeenLastCalledWith([]);
      expect(screen.queryByText("First content")).not.toBeInTheDocument();
    });

    it("should not expand items on click when the parent ignores selection changes", async () => {
      // Given
      const user = userEvent.setup();
      render(<Accordion items={buildItems()} selectedKeys={[]} />);

      // When
      await user.click(screen.getByRole("button", { name: "First item" }));

      // Then
      expect(screen.queryByText("First content")).not.toBeInTheDocument();
    });
  });

  describe("when items are nested", () => {
    it("should render nested accordions sharing the controlled selection", async () => {
      // Given
      const user = userEvent.setup();
      const ControlledAccordion = () => {
        const [keys, setKeys] = useState<string[]>(["parent"]);
        return (
          <Accordion
            items={[
              {
                key: "parent",
                title: "Parent item",
                content: "Parent content",
                items: [
                  {
                    key: "child",
                    title: "Child item",
                    content: "Child content",
                  },
                ],
              },
            ]}
            selectionMode="multiple"
            selectedKeys={keys}
            onSelectionChange={setKeys}
          />
        );
      };
      render(<ControlledAccordion />);
      expect(screen.getByText("Parent content")).toBeVisible();

      // When
      await user.click(screen.getByRole("button", { name: "Child item" }));

      // Then both levels stay expanded
      expect(screen.getByText("Parent content")).toBeVisible();
      expect(screen.getByText("Child content")).toBeVisible();
    });
  });
});
