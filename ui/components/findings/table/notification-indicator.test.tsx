import { render } from "@testing-library/react";
import type { ReactNode } from "react";
import { describe, expect, it, vi } from "vitest";

vi.mock("next/link", () => ({
  default: ({
    children,
    href,
    ...props
  }: {
    children: ReactNode;
    href: string;
  }) => (
    <a href={href} {...props}>
      {children}
    </a>
  ),
}));

vi.mock("@/components/icons", () => ({
  MutedIcon: (props: Record<string, unknown>) => (
    <svg data-testid="muted-icon" {...props} />
  ),
}));

vi.mock("@/components/shadcn", () => ({
  Button: ({
    children,
    asChild,
    ...props
  }: {
    children: ReactNode;
    asChild?: boolean;
  }) =>
    asChild ? (
      children
    ) : (
      <button type="button" {...props}>
        {children}
      </button>
    ),
}));

vi.mock("@/components/shadcn/popover", () => ({
  Popover: ({ children }: { children: ReactNode }) => <div>{children}</div>,
  PopoverTrigger: ({ children }: { children: ReactNode }) => <>{children}</>,
  PopoverContent: ({ children }: { children: ReactNode }) => (
    <div>{children}</div>
  ),
}));

vi.mock("@/components/shadcn/tooltip", () => ({
  Tooltip: ({ children }: { children: ReactNode }) => <div>{children}</div>,
  TooltipTrigger: ({ children }: { children: ReactNode }) => <>{children}</>,
  TooltipContent: ({ children }: { children: ReactNode }) => (
    <div>{children}</div>
  ),
}));

import { NotificationIndicator } from "./notification-indicator";

describe("NotificationIndicator", () => {
  it("reserves the muted slot for delta-only rows when requested", () => {
    const { container } = render(
      <NotificationIndicator delta="new" showDeltaWhenMuted reserveMutedSlot />,
    );

    const root = container.querySelector(
      '[data-slot="notification-indicator"]',
    );
    const mutedSlot = container.querySelector(
      '[data-slot="notification-muted-slot"]',
    );
    const deltaSlot = container.querySelector(
      '[data-slot="notification-delta-slot"]',
    );

    expect(root).toBeInTheDocument();
    expect(mutedSlot).toBeInTheDocument();
    expect(deltaSlot).toBeInTheDocument();
    expect(mutedSlot?.children).toHaveLength(0);
    expect(deltaSlot?.children).toHaveLength(1);
  });

  it("keeps both reserved slots populated for muted rows with delta", () => {
    const { container } = render(
      <NotificationIndicator
        delta="changed"
        isMuted
        mutedReason="False positive"
        showDeltaWhenMuted
        reserveMutedSlot
      />,
    );

    const mutedSlot = container.querySelector(
      '[data-slot="notification-muted-slot"]',
    );
    const deltaSlot = container.querySelector(
      '[data-slot="notification-delta-slot"]',
    );

    expect(mutedSlot?.children).toHaveLength(1);
    expect(deltaSlot?.children).toHaveLength(1);
  });
});
