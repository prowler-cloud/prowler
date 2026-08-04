import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { WATCHLIST_PIN_STATE } from "@/types/compliance-watchlist";

import { WatchlistToggle } from "./watchlist-toggle";

const {
  addComplianceToWatchlistMock,
  removeComplianceFromWatchlistMock,
  bulkUpdateComplianceWatchlistMock,
  toastMock,
} = vi.hoisted(() => ({
  addComplianceToWatchlistMock: vi.fn(),
  removeComplianceFromWatchlistMock: vi.fn(),
  bulkUpdateComplianceWatchlistMock: vi.fn(),
  toastMock: vi.fn(),
}));

vi.mock("@/actions/compliance-watchlist", () => ({
  addComplianceToWatchlist: addComplianceToWatchlistMock,
  removeComplianceFromWatchlist: removeComplianceFromWatchlistMock,
  bulkUpdateComplianceWatchlist: bulkUpdateComplianceWatchlistMock,
}));

vi.mock("@/components/shadcn/toast/use-toast", () => ({
  useToast: () => ({ toast: toastMock }),
}));

const TARGET = { complianceId: "cis_1.4_aws", providerType: "aws" };
const ENTRY_ID = "3fa85f64-5717-4562-b3fc-2c963f66afa6";

beforeEach(() => {
  addComplianceToWatchlistMock.mockResolvedValue({ success: "ok" });
  removeComplianceFromWatchlistMock.mockResolvedValue({ success: "ok" });
  bulkUpdateComplianceWatchlistMock.mockResolvedValue({ success: "ok" });
});

describe("WatchlistToggle", () => {
  it("adds an unpinned framework", async () => {
    // Given
    const user = userEvent.setup();
    render(
      <WatchlistToggle target={TARGET} state={WATCHLIST_PIN_STATE.UNPINNED} />,
    );

    // When
    await user.click(screen.getByRole("button", { name: "Watchlist" }));

    // Then
    await waitFor(() =>
      expect(addComplianceToWatchlistMock).toHaveBeenCalledWith(TARGET),
    );
    expect(toastMock).toHaveBeenCalledWith(
      expect.objectContaining({ title: "Success!" }),
    );
  });

  it("removes a pinned framework by entry id", async () => {
    // Given
    const user = userEvent.setup();
    render(
      <WatchlistToggle
        target={TARGET}
        state={WATCHLIST_PIN_STATE.PINNED}
        entryId={ENTRY_ID}
      />,
    );

    // When
    await user.click(screen.getByRole("button", { name: "Watchlist" }));

    // Then
    await waitFor(() =>
      expect(removeComplianceFromWatchlistMock).toHaveBeenCalledWith(ENTRY_ID),
    );
  });

  it("falls back to bulk removal when the entry id is unavailable", async () => {
    // Given
    const user = userEvent.setup();
    render(
      <WatchlistToggle target={TARGET} state={WATCHLIST_PIN_STATE.PINNED} />,
    );

    // When
    await user.click(screen.getByRole("button", { name: "Watchlist" }));

    // Then
    await waitFor(() =>
      expect(bulkUpdateComplianceWatchlistMock).toHaveBeenCalledWith({
        add: [],
        remove: [TARGET],
      }),
    );
  });

  it("exposes the optimistic state while the request is pending", async () => {
    // Given
    const user = userEvent.setup();
    let resolveAction: (value: { success: string }) => void = () => {};
    addComplianceToWatchlistMock.mockReturnValue(
      new Promise((resolve) => {
        resolveAction = resolve;
      }),
    );
    render(
      <WatchlistToggle target={TARGET} state={WATCHLIST_PIN_STATE.UNPINNED} />,
    );

    // When
    await user.click(screen.getByRole("button", { name: "Watchlist" }));

    // Then
    await waitFor(() =>
      expect(screen.getByRole("button", { name: "Watchlist" })).toHaveAttribute(
        "aria-pressed",
        "true",
      ),
    );
    resolveAction({ success: "ok" });
  });

  it("rolls back and reports an API error", async () => {
    // Given
    const user = userEvent.setup();
    addComplianceToWatchlistMock.mockResolvedValue({ error: "Forbidden" });
    render(
      <WatchlistToggle target={TARGET} state={WATCHLIST_PIN_STATE.UNPINNED} />,
    );

    // When
    await user.click(screen.getByRole("button", { name: "Watchlist" }));

    // Then
    await waitFor(() =>
      expect(toastMock).toHaveBeenCalledWith(
        expect.objectContaining({ variant: "destructive" }),
      ),
    );
    await waitFor(() =>
      expect(screen.getByRole("button", { name: "Watchlist" })).toHaveAttribute(
        "aria-pressed",
        "false",
      ),
    );
  });
});
