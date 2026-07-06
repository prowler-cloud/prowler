import { render, screen, waitFor } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";

import type { LighthouseV2Session } from "@/app/(prowler)/lighthouse/_types";

import { LighthouseV2SidebarChat } from "./lighthouse-v2-sidebar-chat";

const navigationMocks = vi.hoisted(() => ({
  push: vi.fn(),
  searchParams: "",
}));

vi.mock("next/navigation", () => ({
  useRouter: () => ({ push: navigationMocks.push }),
  useSearchParams: () => new URLSearchParams(navigationMocks.searchParams),
}));

const actions = vi.hoisted(() => ({
  archiveLighthouseV2Session: vi.fn(),
  getLighthouseV2Sessions: vi.fn(),
}));

vi.mock("@/app/(prowler)/lighthouse/_actions", () => ({
  archiveLighthouseV2Session: actions.archiveLighthouseV2Session,
  getLighthouseV2Sessions: actions.getLighthouseV2Sessions,
}));

describe("LighthouseV2SidebarChat", () => {
  beforeEach(() => {
    navigationMocks.push.mockReset();
    navigationMocks.searchParams = "";
    actions.archiveLighthouseV2Session.mockReset();
    actions.getLighthouseV2Sessions.mockReset();
  });

  it("marks the URL session as active in chat history", async () => {
    // Given
    navigationMocks.searchParams = "session=session-active";
    actions.getLighthouseV2Sessions.mockResolvedValue({
      data: [
        session({ id: "session-active", title: "Active chat" }),
        session({ id: "session-other", title: "Other chat" }),
      ],
    });

    // When
    render(<LighthouseV2SidebarChat isOpen />);

    // Then
    const activeSession = await screen.findByRole("button", {
      name: /^Active chat/,
    });
    const otherSession = screen.getByRole("button", {
      name: /^Other chat/,
    });

    await waitFor(() =>
      expect(activeSession.parentElement).toHaveClass("bg-bg-neutral-tertiary"),
    );
    expect(otherSession.parentElement).not.toHaveClass(
      "bg-bg-neutral-tertiary",
    );
  });
});

function session(
  overrides: Partial<LighthouseV2Session> = {},
): LighthouseV2Session {
  return {
    id: "session-1",
    title: "Session",
    isArchived: false,
    insertedAt: "2026-06-30T09:00:00Z",
    updatedAt: new Date().toISOString(),
    ...overrides,
  };
}
