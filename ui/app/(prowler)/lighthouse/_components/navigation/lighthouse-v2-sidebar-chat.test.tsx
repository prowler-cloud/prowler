import { act, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";

import {
  LIGHTHOUSE_V2_SESSION_ARCHIVED_EVENT,
  LIGHTHOUSE_V2_SESSIONS_CHANGED_EVENT,
} from "@/app/(prowler)/lighthouse/_lib/session-events";
import type { LighthouseV2Session } from "@/app/(prowler)/lighthouse/_types";

import { LighthouseV2SidebarChat } from "./lighthouse-v2-sidebar-chat";

const navigationMocks = vi.hoisted(() => ({
  push: vi.fn(),
  searchParams: "",
  pathname: "/lighthouse",
}));

vi.mock("next/navigation", () => ({
  usePathname: () => navigationMocks.pathname,
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
    navigationMocks.pathname = "/lighthouse";
    actions.archiveLighthouseV2Session.mockReset();
    actions.getLighthouseV2Sessions.mockReset();
    window.history.replaceState(null, "", "/lighthouse");
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

  it("navigates back to a new chat when archiving the open session", async () => {
    // Given: the archived session is the one currently open (in the URL)
    const user = userEvent.setup();
    navigationMocks.searchParams = "session=session-active";
    actions.getLighthouseV2Sessions.mockResolvedValue({
      data: [session({ id: "session-active", title: "Active chat" })],
    });
    actions.archiveLighthouseV2Session.mockResolvedValue({
      data: session({ id: "session-active", isArchived: true }),
    });
    const archivedIds: string[] = [];
    const recordArchivedId = (event: Event) => {
      archivedIds.push(
        (event as CustomEvent<{ sessionId: string }>).detail.sessionId,
      );
    };

    try {
      window.addEventListener(
        LIGHTHOUSE_V2_SESSION_ARCHIVED_EVENT,
        recordArchivedId,
      );
      render(<LighthouseV2SidebarChat isOpen />);

      // When
      await user.click(
        await screen.findByRole("button", { name: "Archive Active chat" }),
      );
      await user.click(
        within(screen.getByRole("dialog")).getByRole("button", {
          name: "Archive",
        }),
      );

      // Then: the URL no longer points at the archived (deleted) conversation,
      // and the chat page is told which session died (it may hold a
      // live-created session invisible to the router).
      await waitFor(() =>
        expect(navigationMocks.push).toHaveBeenCalledWith("/lighthouse"),
      );
      expect(archivedIds).toEqual(["session-active"]);
    } finally {
      window.removeEventListener(
        LIGHTHOUSE_V2_SESSION_ARCHIVED_EVENT,
        recordArchivedId,
      );
    }
  });

  it("stays on the open session when archiving a different one", async () => {
    // Given
    const user = userEvent.setup();
    navigationMocks.searchParams = "session=session-active";
    actions.getLighthouseV2Sessions.mockResolvedValue({
      data: [
        session({ id: "session-active", title: "Active chat" }),
        session({ id: "session-other", title: "Other chat" }),
      ],
    });
    actions.archiveLighthouseV2Session.mockResolvedValue({
      data: session({ id: "session-other", isArchived: true }),
    });
    render(<LighthouseV2SidebarChat isOpen />);

    // When
    await user.click(
      await screen.findByRole("button", { name: "Archive Other chat" }),
    );
    await user.click(
      within(screen.getByRole("dialog")).getByRole("button", {
        name: "Archive",
      }),
    );

    // Then
    await waitFor(() =>
      expect(actions.archiveLighthouseV2Session).toHaveBeenCalledWith(
        "session-other",
      ),
    );
    expect(navigationMocks.push).not.toHaveBeenCalled();
  });

  it("disables the new chat button while already on a pristine new chat", async () => {
    // Given: /lighthouse with no session in any URL
    actions.getLighthouseV2Sessions.mockResolvedValue({ data: [] });

    // When
    render(<LighthouseV2SidebarChat isOpen />);

    // Then
    expect(
      await screen.findByRole("button", { name: "New chat" }),
    ).toBeDisabled();
  });

  it("enables the new chat button when a conversation is open", async () => {
    // Given
    navigationMocks.searchParams = "session=session-active";
    actions.getLighthouseV2Sessions.mockResolvedValue({
      data: [session({ id: "session-active", title: "Active chat" })],
    });

    // When
    render(<LighthouseV2SidebarChat isOpen />);

    // Then
    expect(
      await screen.findByRole("button", { name: "New chat" }),
    ).toBeEnabled();
  });

  it("enables the new chat button when the chat creates its session in place", async () => {
    // Given: a pristine new chat
    actions.getLighthouseV2Sessions.mockResolvedValue({ data: [] });
    render(<LighthouseV2SidebarChat isOpen />);
    expect(
      await screen.findByRole("button", { name: "New chat" }),
    ).toBeDisabled();

    // When: the first message creates the session via replaceState (Next's
    // router never sees this URL) and history listeners are notified
    act(() => {
      window.history.replaceState(null, "", "/lighthouse?session=live-1");
      window.dispatchEvent(new Event(LIGHTHOUSE_V2_SESSIONS_CHANGED_EVENT));
    });

    // Then
    await waitFor(() =>
      expect(screen.getByRole("button", { name: "New chat" })).toBeEnabled(),
    );
  });

  it("disables the collapsed new chat button too on a pristine new chat", async () => {
    // Given
    actions.getLighthouseV2Sessions.mockResolvedValue({ data: [] });

    // When
    render(<LighthouseV2SidebarChat isOpen={false} />);

    // Then
    await waitFor(() =>
      expect(screen.getByRole("button", { name: "New chat" })).toBeDisabled(),
    );
  });

  it("keeps the new chat button enabled outside the chat page", async () => {
    // Given: chat sidebar mode active while browsing another page
    navigationMocks.pathname = "/findings";
    window.history.replaceState(null, "", "/findings");
    actions.getLighthouseV2Sessions.mockResolvedValue({ data: [] });

    // When
    render(<LighthouseV2SidebarChat isOpen />);

    // Then
    expect(
      await screen.findByRole("button", { name: "New chat" }),
    ).toBeEnabled();
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
