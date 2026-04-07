import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";

// ---------------------------------------------------------------------------
// Hoist mocks to avoid deep dependency chains
// ---------------------------------------------------------------------------

const { MuteFindingsModalMock } = vi.hoisted(() => ({
  MuteFindingsModalMock: vi.fn(() => null),
}));

vi.mock("./mute-findings-modal", () => ({
  MuteFindingsModal: MuteFindingsModalMock,
}));

vi.mock("next/navigation", () => ({
  redirect: vi.fn(),
}));

// ---------------------------------------------------------------------------
// Import after mocks
// ---------------------------------------------------------------------------

import { FloatingMuteButton } from "./floating-mute-button";

// ---------------------------------------------------------------------------
// Fix 3: onBeforeOpen rejection resets isResolving
// ---------------------------------------------------------------------------

describe("FloatingMuteButton — onBeforeOpen error handling", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.spyOn(console, "error").mockImplementation(() => {});
  });

  it("should reset isResolving (re-enable button) when onBeforeOpen rejects", async () => {
    // Given — onBeforeOpen always throws
    const onBeforeOpen = vi.fn().mockRejectedValue(new Error("Network error"));
    const user = userEvent.setup();

    render(
      <FloatingMuteButton
        selectedCount={3}
        selectedFindingIds={[]}
        onBeforeOpen={onBeforeOpen}
      />,
    );

    const button = screen.getByRole("button");

    // When — click the button (triggers onBeforeOpen which rejects)
    await user.click(button);

    // Then — button should NOT be disabled (isResolving reset to false)
    await waitFor(() => {
      expect(button).not.toBeDisabled();
    });
  });

  it("should log the error when onBeforeOpen rejects", async () => {
    // Given
    const error = new Error("Fetch failed");
    const onBeforeOpen = vi.fn().mockRejectedValue(error);
    const consoleSpy = vi.spyOn(console, "error").mockImplementation(() => {});
    const user = userEvent.setup();

    render(
      <FloatingMuteButton
        selectedCount={2}
        selectedFindingIds={[]}
        onBeforeOpen={onBeforeOpen}
      />,
    );

    // When
    await user.click(screen.getByRole("button"));

    // Then — error was logged
    await waitFor(() => {
      expect(consoleSpy).toHaveBeenCalled();
    });
  });

  it("should open modal when onBeforeOpen resolves successfully", async () => {
    // Given
    const onBeforeOpen = vi.fn().mockResolvedValue(["id-1", "id-2"]);
    const user = userEvent.setup();

    render(
      <FloatingMuteButton
        selectedCount={2}
        selectedFindingIds={[]}
        onBeforeOpen={onBeforeOpen}
      />,
    );

    // When
    await user.click(screen.getByRole("button"));

    // Then — modal opened (MuteFindingsModal called with isOpen=true)
    await waitFor(() => {
      const lastCall = (
        MuteFindingsModalMock.mock.calls as unknown as Array<
          [{ isOpen: boolean; findingIds: string[] }]
        >
      ).at(-1);
      expect(lastCall?.[0]?.isOpen).toBe(true);
    });
  });
});
