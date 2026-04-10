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

function deferredPromise<T>() {
  let resolve!: (value: T) => void;
  let reject!: (reason?: unknown) => void;
  const promise = new Promise<T>((res, rej) => {
    resolve = res;
    reject = rej;
  });

  return { promise, resolve, reject };
}

// ---------------------------------------------------------------------------
// Fix 3: onBeforeOpen rejection resets isResolving
// ---------------------------------------------------------------------------

describe("FloatingMuteButton — onBeforeOpen error handling", () => {
  beforeEach(() => {
    vi.clearAllMocks();
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

  it("should show the preparation error in the modal when onBeforeOpen rejects", async () => {
    // Given
    const onBeforeOpen = vi.fn().mockRejectedValue(new Error("Fetch failed"));
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

    // Then
    await waitFor(() => {
      const lastCall = (
        MuteFindingsModalMock.mock.calls as unknown as Array<
          [
            {
              isOpen: boolean;
              isPreparing?: boolean;
              preparationError?: string | null;
            },
          ]
        >
      ).at(-1);

      expect(lastCall?.[0]).toMatchObject({
        isOpen: true,
        isPreparing: false,
        preparationError:
          "We couldn't prepare this mute action. Please try again.",
      });
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
          [
            {
              isOpen: boolean;
              findingIds: string[];
              isPreparing?: boolean;
            },
          ]
        >
      ).at(-1);
      expect(lastCall?.[0]?.isOpen).toBe(true);
    });
  });

  it("should open the modal immediately in preparing state while IDs are still resolving", async () => {
    // Given
    const deferred = deferredPromise<string[]>();
    const onBeforeOpen = vi.fn().mockReturnValue(deferred.promise);
    const user = userEvent.setup();

    render(
      <FloatingMuteButton
        selectedCount={3}
        selectedFindingIds={["group-1", "group-2", "group-3"]}
        onBeforeOpen={onBeforeOpen}
      />,
    );

    // When
    await user.click(screen.getByRole("button"));

    // Then
    const preparingCall = (
      MuteFindingsModalMock.mock.calls as unknown as Array<
        [
          {
            isOpen: boolean;
            findingIds: string[];
            isPreparing?: boolean;
          },
        ]
      >
    ).at(-1);

    expect(preparingCall?.[0]).toMatchObject({
      isOpen: true,
      isPreparing: true,
      findingIds: [],
    });

    // And when the IDs resolve
    deferred.resolve(["id-1", "id-2"]);

    await waitFor(() => {
      const resolvedCall = (
        MuteFindingsModalMock.mock.calls as unknown as Array<
          [
            {
              isOpen: boolean;
              findingIds: string[];
              isPreparing?: boolean;
            },
          ]
        >
      ).at(-1);

      expect(resolvedCall?.[0]).toMatchObject({
        isOpen: true,
        isPreparing: false,
        findingIds: ["id-1", "id-2"],
      });
    });
  });
});
