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
    await user.click(screen.getByRole("button", { name: "Mute" }));

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
    await user.click(screen.getByRole("button", { name: "Mute" }));

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
    await user.click(screen.getByRole("button", { name: "Mute" }));

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
    await user.click(screen.getByRole("button", { name: "Mute" }));

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

  it("should route Send to Jira through the action chooser without opening mute", async () => {
    // Given
    const onSendToJira = vi.fn();
    const user = userEvent.setup();

    render(
      <FloatingMuteButton
        selectedCount={1}
        selectedFindingIds={["finding-1"]}
        canSendToJira
        onSendToJira={onSendToJira}
      />,
    );

    // When
    await user.click(screen.getByRole("button", { name: "Mute (1)" }));
    await user.click(screen.getByRole("button", { name: "Send to Jira" }));

    // Then
    expect(onSendToJira).toHaveBeenCalledTimes(1);
    const modalCalls = MuteFindingsModalMock.mock.calls as unknown as Array<
      [{ isOpen?: boolean }]
    >;
    expect(modalCalls.some(([props]) => props.isOpen === true)).toBe(false);
  });

  it("should render custom mixed-selection action labels", async () => {
    // Given
    const user = userEvent.setup();

    render(
      <FloatingMuteButton
        selectedCount={2}
        selectedFindingIds={["group-1", "finding-1"]}
        label="1 Group and 1 Finding selected"
        muteLabel="Mute 1 Group and 1 Finding"
        sendToJiraLabel="Send 1 Group and 1 Finding to Jira"
        showSendToJira
      />,
    );

    // When
    await user.click(
      screen.getByRole("button", {
        name: "1 Group and 1 Finding selected",
      }),
    );

    // Then
    expect(
      screen.getByRole("button", {
        name: "Mute 1 Group and 1 Finding",
      }),
    ).toBeVisible();
    expect(
      screen.getByRole("button", {
        name: "Send to Jira",
      }),
    ).toHaveTextContent("Send 1 Group and 1 Finding to Jira");
  });

  it("should show disabled Cloud-only Jira action in the chooser", async () => {
    // Given
    const onSendToJira = vi.fn();
    const user = userEvent.setup();

    render(
      <FloatingMuteButton
        selectedCount={1}
        selectedFindingIds={["finding-1"]}
        showSendToJira
        canSendToJira={false}
        onSendToJira={onSendToJira}
      />,
    );

    // When
    await user.click(screen.getByRole("button", { name: "Mute (1)" }));
    const jiraButton = screen.getByRole("button", { name: "Send to Jira" });

    // Then
    expect(jiraButton).toBeVisible();
    expect(jiraButton).toBeDisabled();
    const cloudBadgeLink = screen.getByRole("link", {
      name: "Available only in Prowler Cloud",
    });
    expect(cloudBadgeLink).toHaveTextContent("Available only in Prowler Cloud");
    expect(cloudBadgeLink).toHaveAttribute(
      "href",
      "https://prowler.com/pricing",
    );
    expect(jiraButton).not.toContainElement(cloudBadgeLink);
    expect(onSendToJira).not.toHaveBeenCalled();

    // When
    await user.hover(jiraButton.parentElement!);

    // Then
    const tooltipTexts = await screen.findAllByText(
      "Available only in Prowler Cloud",
    );
    expect(tooltipTexts[0]).toBeVisible();
  });
});
