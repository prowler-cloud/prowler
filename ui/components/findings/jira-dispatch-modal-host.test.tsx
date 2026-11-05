import { render } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { createJiraTargetSelection } from "@/lib/jira-dispatch-selection";
import { useJiraDispatchStore } from "@/store";
import { JIRA_DISPATCH_MODE, JIRA_DISPATCH_TARGET } from "@/types/integrations";

const { SendToJiraModalMock, isGroupedJiraDispatchEnabledMock } = vi.hoisted(
  () => ({
    SendToJiraModalMock: vi.fn(() => null),
    isGroupedJiraDispatchEnabledMock: vi.fn(() => true),
  }),
);

vi.mock("./send-to-jira-modal", () => ({
  SendToJiraModal: SendToJiraModalMock,
}));

vi.mock("@/lib/deployment", async (importOriginal) => ({
  ...(await importOriginal<typeof import("@/lib/deployment")>()),
  isGroupedJiraDispatchEnabled: isGroupedJiraDispatchEnabledMock,
}));

import { JiraDispatchModalHost } from "./jira-dispatch-modal-host";

describe("JiraDispatchModalHost", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    useJiraDispatchStore.getState().closeJiraDispatch();
  });

  it("renders one modal with derived grouped configuration", () => {
    // Given
    const selection = createJiraTargetSelection(
      ["check-1"],
      JIRA_DISPATCH_TARGET.CHECK_ID,
    )!;
    useJiraDispatchStore.getState().openJiraDispatch({
      selection,
      selectedResourceCount: 3,
      findingTitle: "Check title",
    });

    // When
    render(<JiraDispatchModalHost />);

    // Then
    expect(SendToJiraModalMock).toHaveBeenCalledWith(
      expect.objectContaining({
        isOpen: true,
        selection,
        findingTitle: "Check title",
        defaultDispatchMode: JIRA_DISPATCH_MODE.GROUPED,
        canChooseGroupedDispatch: true,
      }),
      undefined,
    );
  });

  it("does not render without an active payload", () => {
    // Given / When
    render(<JiraDispatchModalHost />);

    // Then
    expect(SendToJiraModalMock).not.toHaveBeenCalled();
  });
});
