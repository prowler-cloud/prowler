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

const AWS_TARGET = { complianceId: "cis_1.4_aws", providerType: "aws" };
const ENTRY_ID = "3fa85f64-5717-4562-b3fc-2c963f66afa6";

beforeEach(() => {
  addComplianceToWatchlistMock.mockResolvedValue({ success: "ok" });
  removeComplianceFromWatchlistMock.mockResolvedValue({ success: "ok" });
  bulkUpdateComplianceWatchlistMock.mockResolvedValue({ success: "ok" });
});

describe("WatchlistToggle rendering", () => {
  it("offers to pin an unpinned framework", () => {
    render(
      <WatchlistToggle
        targets={[AWS_TARGET]}
        state={WATCHLIST_PIN_STATE.UNPINNED}
      />,
    );

    expect(
      screen.getByRole("button", { name: "Watchlist" }),
    ).toBeInTheDocument();
  });

  it("offers to unpin a pinned framework", () => {
    render(
      <WatchlistToggle
        targets={[AWS_TARGET]}
        state={WATCHLIST_PIN_STATE.PINNED}
        entryId={ENTRY_ID}
      />,
    );

    expect(
      screen.getByRole("button", { name: "Watchlist" }),
    ).toBeInTheDocument();
  });

  it("renders as an icon-only control, keeping the label accessible", () => {
    render(
      <WatchlistToggle
        targets={[AWS_TARGET]}
        state={WATCHLIST_PIN_STATE.UNPINNED}
      />,
    );

    // The card is dense enough that a labelled link stole a whole row; the
    // label lives in the accessible name and the tooltip instead.
    expect(screen.getByRole("button", { name: "Watchlist" }).textContent).toBe(
      "",
    );
  });

  it("renders a pinned universal framework from its single `*` target", () => {
    render(
      <WatchlistToggle
        targets={[{ complianceId: "dora_2022_2554", providerType: "*" }]}
        state={WATCHLIST_PIN_STATE.PINNED}
        entryId="3fa85f64-5717-4562-b3fc-2c963f66afa6"
      />,
    );

    const button = screen.getByRole("button", {
      name: "Watchlist",
    });
    expect(button).toBeInTheDocument();
    expect(button).toHaveAttribute("data-pin-state", "pinned");
  });
});

describe("WatchlistToggle mutations", () => {
  it("pins a single framework with the single-entry endpoint", async () => {
    const user = userEvent.setup();
    render(
      <WatchlistToggle
        targets={[AWS_TARGET]}
        state={WATCHLIST_PIN_STATE.UNPINNED}
      />,
    );

    await user.click(screen.getByRole("button"));

    await waitFor(() =>
      expect(addComplianceToWatchlistMock).toHaveBeenCalledWith(AWS_TARGET),
    );
    expect(bulkUpdateComplianceWatchlistMock).not.toHaveBeenCalled();
  });

  it("unpins a single framework by its watchlist entry id", async () => {
    const user = userEvent.setup();
    render(
      <WatchlistToggle
        targets={[AWS_TARGET]}
        state={WATCHLIST_PIN_STATE.PINNED}
        entryId={ENTRY_ID}
      />,
    );

    await user.click(screen.getByRole("button"));

    await waitFor(() =>
      expect(removeComplianceFromWatchlistMock).toHaveBeenCalledWith(ENTRY_ID),
    );
  });

  it("pins a universal framework through one bulk call, not N single calls", async () => {
    const user = userEvent.setup();
    const targets = [
      AWS_TARGET,
      { complianceId: "cis_1.4_aws", providerType: "azure" },
      { complianceId: "cis_1.4_aws", providerType: "gcp" },
    ];
    render(
      <WatchlistToggle
        targets={targets}
        state={WATCHLIST_PIN_STATE.UNPINNED}
      />,
    );

    await user.click(screen.getByRole("button"));

    await waitFor(() =>
      expect(bulkUpdateComplianceWatchlistMock).toHaveBeenCalledWith({
        add: targets,
        remove: [],
      }),
    );
    expect(addComplianceToWatchlistMock).not.toHaveBeenCalled();
  });

  it("unpins several cards in one call when no single entry id is known", async () => {
    const user = userEvent.setup();
    const targets = [
      AWS_TARGET,
      { complianceId: "cis_1.4_aws", providerType: "azure" },
    ];
    render(
      <WatchlistToggle targets={targets} state={WATCHLIST_PIN_STATE.PINNED} />,
    );

    await user.click(screen.getByRole("button"));

    await waitFor(() =>
      expect(bulkUpdateComplianceWatchlistMock).toHaveBeenCalledWith({
        add: [],
        remove: targets,
      }),
    );
  });

  it("shows the pinned label optimistically before the server answers", async () => {
    const user = userEvent.setup();
    let resolveAction: (value: { success: string }) => void = () => {};
    addComplianceToWatchlistMock.mockReturnValue(
      new Promise((resolve) => {
        resolveAction = resolve;
      }),
    );

    render(
      <WatchlistToggle
        targets={[AWS_TARGET]}
        state={WATCHLIST_PIN_STATE.UNPINNED}
      />,
    );

    await user.click(screen.getByRole("button"));

    // The pin state itself, not merely the button's presence: the accessible
    // name never changes, so asserting on it would pass with the optimistic
    // update removed entirely.
    await waitFor(() =>
      expect(screen.getByRole("button", { name: "Watchlist" })).toHaveAttribute(
        "data-pin-state",
        WATCHLIST_PIN_STATE.PINNED,
      ),
    );
    expect(screen.getByRole("button", { name: "Watchlist" })).toHaveAttribute(
      "aria-pressed",
      "true",
    );

    resolveAction({ success: "ok" });
  });

  it("reverts to the unpinned label and toasts when the API rejects the change", async () => {
    const user = userEvent.setup();
    addComplianceToWatchlistMock.mockResolvedValue({
      error: "The tenant has no provider of type aws.",
    });

    render(
      <WatchlistToggle
        targets={[AWS_TARGET]}
        state={WATCHLIST_PIN_STATE.UNPINNED}
      />,
    );

    await user.click(screen.getByRole("button"));

    await waitFor(() =>
      expect(toastMock).toHaveBeenCalledWith(
        expect.objectContaining({ variant: "destructive" }),
      ),
    );
    // `useOptimistic` reverts once the transition settles, so the rejected
    // change must leave the card reading exactly as it did before the click.
    await waitFor(() =>
      expect(screen.getByRole("button", { name: "Watchlist" })).toHaveAttribute(
        "data-pin-state",
        WATCHLIST_PIN_STATE.UNPINNED,
      ),
    );
    expect(screen.getByRole("button", { name: "Watchlist" })).toHaveAttribute(
      "aria-pressed",
      "false",
    );
  });

  it("toasts on success", async () => {
    const user = userEvent.setup();

    render(
      <WatchlistToggle
        targets={[AWS_TARGET]}
        state={WATCHLIST_PIN_STATE.UNPINNED}
      />,
    );

    await user.click(screen.getByRole("button"));

    await waitFor(() =>
      expect(toastMock).toHaveBeenCalledWith(
        expect.objectContaining({ title: expect.stringMatching(/success/i) }),
      ),
    );
  });

  it("does not activate the surrounding card when toggling", async () => {
    const user = userEvent.setup();
    const onCardActivate = vi.fn();

    render(
      <div
        role="button"
        aria-label="Open CIS 1.4"
        tabIndex={0}
        onClick={onCardActivate}
      >
        <WatchlistToggle
          targets={[AWS_TARGET]}
          state={WATCHLIST_PIN_STATE.UNPINNED}
        />
      </div>,
    );

    await user.click(screen.getByRole("button", { name: "Watchlist" }));

    expect(onCardActivate).not.toHaveBeenCalled();
  });

  it("ignores a click with no target to act on", async () => {
    const user = userEvent.setup();
    render(
      <WatchlistToggle targets={[]} state={WATCHLIST_PIN_STATE.UNPINNED} />,
    );

    await user.click(screen.getByRole("button"));

    expect(addComplianceToWatchlistMock).not.toHaveBeenCalled();
    expect(bulkUpdateComplianceWatchlistMock).not.toHaveBeenCalled();
  });
});
