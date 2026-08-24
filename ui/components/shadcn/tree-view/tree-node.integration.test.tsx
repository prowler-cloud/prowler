import { describe, expect, it, vi } from "vitest";
import { userEvent } from "vitest/browser";

const useReducedMotionMock = vi.hoisted(() => vi.fn());

vi.mock("framer-motion", async () => {
  const React = await import("react");

  return {
    AnimatePresence: ({ children }: { children: React.ReactNode }) => children,
    motion: {
      ul: ({
        children,
        transition,
        ...props
      }: React.ComponentProps<"ul"> & {
        transition?: { duration?: number };
      }) => (
        <ul data-motion-duration={transition?.duration} {...props}>
          {children}
        </ul>
      ),
    },
    useReducedMotion: useReducedMotionMock,
  };
});

import { render } from "@/__tests__/render-browser";

import { TreeView } from "./tree-view";

const treeData = [
  {
    id: "registry-root",
    name: "Registry root",
    children: [{ id: "registry-child", name: "Registry child" }],
  },
];

describe("TreeView", () => {
  it("keeps keyboard expansion operable with normal motion", async () => {
    // Given
    useReducedMotionMock.mockReturnValue(false);
    const screen = await render(<TreeView data={treeData} />);
    const root = screen.getByRole("treeitem", { name: "Registry root" });
    root.element().focus();

    // When
    await userEvent.keyboard("{Enter}");

    // Then
    await expect.element(root).toHaveAttribute("aria-expanded", "true");
    await expect
      .element(screen.getByRole("group"))
      .toHaveAttribute("data-motion-duration", "0.2");

    // When
    await userEvent.keyboard(" ");

    // Then
    await expect.element(root).toHaveAttribute("aria-expanded", "false");

    // When
    await userEvent.keyboard("{ArrowRight}");

    // Then
    await expect.element(root).toHaveAttribute("aria-expanded", "true");

    // When
    await userEvent.keyboard("{ArrowLeft}");

    // Then
    await expect.element(root).toHaveAttribute("aria-expanded", "false");
  });

  it("uses zero-duration expansion when reduced motion is requested", async () => {
    // Given
    useReducedMotionMock.mockReturnValue(true);
    const screen = await render(<TreeView data={treeData} />);
    const root = screen.getByRole("treeitem", { name: "Registry root" });

    // When
    await userEvent.click(root);

    // Then
    await expect.element(root).toHaveAttribute("aria-expanded", "true");
    await expect
      .element(screen.getByRole("group"))
      .toHaveAttribute("data-motion-duration", "0");

    // When
    await userEvent.keyboard("{ArrowLeft}");

    // Then
    await expect.element(root).toHaveAttribute("aria-expanded", "false");
  });
});
