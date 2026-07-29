import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import type { LighthouseV2Session } from "@/app/(prowler)/lighthouse/_types";

import { LighthouseV2SessionHistory } from "./lighthouse-v2-session-history";

describe("LighthouseV2SessionHistory", () => {
  beforeEach(() => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date("2026-06-25T12:00:00Z"));
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it("keeps the session title truncated and the age label visible without horizontal overflow", () => {
    // Given / When
    renderHistory({
      sessions: [
        session({
          id: "session-today",
          title:
            "This is a very long Lighthouse conversation title that must fit next to the age label",
          updatedAt: "2026-06-25T09:00:00Z",
        }),
      ],
    });

    // Then
    const sessionButton = screen.getByRole("button", {
      name: /This is a very long Lighthouse conversation title.*Today/,
    });
    const title = within(sessionButton).getByText(
      /This is a very long Lighthouse conversation title/i,
    );
    const age = within(sessionButton).getByText("Today");

    expect(sessionButton).toHaveClass("min-w-0", "overflow-hidden");
    expect(sessionButton.parentElement).toHaveClass(
      "min-w-0",
      "overflow-hidden",
    );
    expect(title).toHaveClass("min-w-0", "flex-1", "truncate");
    expect(age).toHaveClass("shrink-0", "whitespace-nowrap");
  });

  it("renders session age as numeric day labels instead of compact counters", () => {
    // Given / When
    renderHistory({
      sessions: [
        session({
          id: "session-today",
          title: "Today session",
          updatedAt: "2026-06-25T09:00:00Z",
        }),
        session({
          id: "session-one-day",
          title: "One day session",
          updatedAt: "2026-06-24T09:00:00Z",
        }),
        session({
          id: "session-two-days",
          title: "Two days session",
          updatedAt: "2026-06-23T09:00:00Z",
        }),
        session({
          id: "session-thirty-days",
          title: "Thirty days session",
          updatedAt: "2026-05-26T09:00:00Z",
        }),
      ],
    });

    // Then
    expect(screen.getByText("Today")).toBeInTheDocument();
    expect(screen.getByText("1 day")).toBeInTheDocument();
    expect(screen.getByText("2 days")).toBeInTheDocument();
    expect(screen.getByText("30 days")).toBeInTheDocument();
    expect(screen.queryByText("today")).not.toBeInTheDocument();
    expect(screen.queryByText("1d")).not.toBeInTheDocument();
    expect(screen.queryByText("2d")).not.toBeInTheDocument();
    expect(screen.queryByText("30d")).not.toBeInTheDocument();
    expect(screen.queryByText("one day")).not.toBeInTheDocument();
    expect(screen.queryByText("thirty days")).not.toBeInTheDocument();
  });

  it("filters visible sessions by the current search value", () => {
    // Given / When
    renderHistory({
      search: "threat",
      sessions: [
        session({
          id: "session-threat",
          title: "Threat model review",
          updatedAt: "2026-06-25T09:00:00Z",
        }),
        session({
          id: "session-compliance",
          title: "Compliance gap analysis",
          updatedAt: "2026-06-25T09:00:00Z",
        }),
      ],
    });

    // Then
    expect(screen.getByText("Threat model review")).toBeInTheDocument();
    expect(
      screen.queryByText("Compliance gap analysis"),
    ).not.toBeInTheDocument();
  });

  it("replaces the age label with the archive action on row hover", () => {
    // Given / When
    renderHistory({
      sessions: [
        session({
          id: "session-today",
          title: "Threat model review",
          updatedAt: "2026-06-25T09:00:00Z",
        }),
      ],
    });

    // Then
    const sessionButton = screen.getByRole("button", {
      name: /Threat model review.*Today/,
    });
    const row = sessionButton.parentElement;
    const age = within(sessionButton).getByText("Today");
    const archiveButton = screen.getByRole("button", {
      name: "Archive Threat model review",
    });

    expect(row).toHaveClass("hover:bg-bg-neutral-tertiary");
    expect(sessionButton).not.toHaveClass("hover:bg-bg-neutral-tertiary");
    expect(age).toHaveClass(
      "transition-opacity",
      "group-hover:opacity-0",
      "group-focus-within:opacity-0",
    );
    expect(archiveButton).toHaveClass(
      "absolute",
      "right-1",
      "opacity-0",
      "group-hover:opacity-100",
      "group-focus-within:opacity-100",
      "hover:text-text-neutral-secondary",
      "active:text-text-neutral-secondary",
    );
  });

  it("opens a confirmation modal before archiving a session", async () => {
    // Given
    vi.useRealTimers();
    const user = userEvent.setup();
    const onArchiveSession = vi.fn();
    renderHistory({
      onArchiveSession,
      sessions: [
        session({
          id: "session-today",
          title: "Threat model review",
          updatedAt: "2026-06-25T09:00:00Z",
        }),
      ],
    });

    // When
    await user.click(
      screen.getByRole("button", { name: "Archive Threat model review" }),
    );

    // Then
    expect(onArchiveSession).not.toHaveBeenCalled();
    const dialog = screen.getByRole("dialog", {
      name: "Are you absolutely sure?",
    });
    expect(
      within(dialog).getByText(
        "This action cannot be undone. This will archive this chat and remove it from your chat history.",
      ),
    ).toBeInTheDocument();

    // When
    await user.click(within(dialog).getByRole("button", { name: "Archive" }));

    // Then
    expect(onArchiveSession).toHaveBeenCalledWith("session-today");
    expect(
      screen.queryByRole("dialog", { name: "Are you absolutely sure?" }),
    ).not.toBeInTheDocument();
  });

  it("explains the new chat button in a tooltip", async () => {
    // Given
    renderHistory();
    vi.useRealTimers();
    const user = userEvent.setup();

    // When
    await user.hover(screen.getByRole("button", { name: "New chat" }));

    // Then
    const tooltip = await screen.findByRole("tooltip");
    expect(tooltip).toHaveTextContent("New chat");
  });

  it("disables the new chat button while already on a new chat", () => {
    // Given / When
    renderHistory({ newChatDisabled: true });

    // Then
    expect(screen.getByRole("button", { name: "New chat" })).toBeDisabled();
  });

  it("shows the full trimmed title in a right-side tooltip", async () => {
    // Given
    const fullTitle =
      "This is the complete Lighthouse conversation title shown in the tooltip";
    renderHistory({
      sessions: [
        session({
          id: "session-tooltip",
          title: fullTitle,
          updatedAt: "2026-06-25T09:00:00Z",
        }),
      ],
    });
    const sessionButton = screen.getByRole("button", {
      name: new RegExp(`${fullTitle}.*Today`),
    });
    vi.useRealTimers();
    const user = userEvent.setup();

    // When
    await user.hover(sessionButton);

    // Then
    const tooltip = await screen.findByRole("tooltip");
    expect(tooltip).toHaveTextContent(fullTitle);
  });
});

function renderHistory(
  props?: Partial<Parameters<typeof LighthouseV2SessionHistory>[0]>,
) {
  return render(
    <LighthouseV2SessionHistory
      sessions={props?.sessions ?? []}
      activeSessionId={props?.activeSessionId}
      search={props?.search ?? ""}
      onSearchChange={props?.onSearchChange ?? vi.fn()}
      onNewSession={props?.onNewSession ?? vi.fn()}
      onOpenSession={props?.onOpenSession ?? vi.fn()}
      onArchiveSession={props?.onArchiveSession ?? vi.fn()}
      newChatDisabled={props?.newChatDisabled}
      compact={props?.compact}
    />,
  );
}

function session(
  overrides: Partial<LighthouseV2Session> = {},
): LighthouseV2Session {
  return {
    id: "session-1",
    title: "Session",
    isArchived: false,
    insertedAt: "2026-06-25T09:00:00Z",
    updatedAt: "2026-06-25T09:00:00Z",
    ...overrides,
  };
}
