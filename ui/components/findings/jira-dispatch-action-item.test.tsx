import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";

import {
  ActionDropdown,
  ActionDropdownItem,
} from "@/components/shadcn/dropdown";
import { createJiraTargetSelection } from "@/lib/jira-dispatch-selection";
import { useCloudUpgradeStore, useJiraDispatchStore } from "@/store";
import {
  JIRA_DISPATCH_TARGET,
  type JiraDispatchTarget,
} from "@/types/integrations";

const { isGroupedJiraDispatchEnabledMock } = vi.hoisted(() => ({
  isGroupedJiraDispatchEnabledMock: vi.fn(() => false),
}));

vi.mock("@/lib/deployment", async (importOriginal) => ({
  ...(await importOriginal<typeof import("@/lib/deployment")>()),
  isGroupedJiraDispatchEnabled: isGroupedJiraDispatchEnabledMock,
}));

import { JiraDispatchActionItem } from "./jira-dispatch-action-item";

const renderAction = (targetIds: string[], targetType: JiraDispatchTarget) => {
  const selection = createJiraTargetSelection(targetIds, targetType)!;

  render(
    <ActionDropdown trigger={<button type="button">Actions</button>}>
      <ActionDropdownItem label="Other action" />
      <JiraDispatchActionItem label="Send to Jira" payload={{ selection }} />
    </ActionDropdown>,
  );
};

describe("JiraDispatchActionItem", () => {
  beforeEach(() => {
    isGroupedJiraDispatchEnabledMock.mockReturnValue(false);
    useCloudUpgradeStore.getState().closeCloudUpgrade();
    useJiraDispatchStore.getState().closeJiraDispatch();
  });

  it("opens Jira modal payload for one Finding", async () => {
    // Given
    const user = userEvent.setup();
    renderAction(["finding-1"], JIRA_DISPATCH_TARGET.FINDING_ID);

    // When
    await user.click(screen.getByRole("button", { name: "Actions" }));
    await user.click(screen.getByRole("menuitem", { name: "Send to Jira" }));

    // Then
    expect(useJiraDispatchStore.getState().activePayload).toMatchObject({
      selection: { targetId: "finding-1" },
    });
    expect(useCloudUpgradeStore.getState().activeFeature).toBeNull();
  });

  it("hides grouped dispatch until it is built, without an upsell", async () => {
    // Given
    const user = userEvent.setup();
    renderAction(["check-1"], JIRA_DISPATCH_TARGET.CHECK_ID);

    // When
    await user.click(screen.getByRole("button", { name: "Actions" }));

    // Then
    expect(
      screen.queryByRole("menuitem", { name: "Send to Jira" }),
    ).not.toBeInTheDocument();
    expect(useCloudUpgradeStore.getState().activeFeature).toBeNull();
    expect(useJiraDispatchStore.getState().activePayload).toBeNull();
  });

  it("opens grouped Jira payload when feature is enabled", async () => {
    // Given
    isGroupedJiraDispatchEnabledMock.mockReturnValue(true);
    const user = userEvent.setup();
    renderAction(["check-1"], JIRA_DISPATCH_TARGET.CHECK_ID);

    // When
    await user.click(screen.getByRole("button", { name: "Actions" }));
    await user.click(screen.getByRole("menuitem", { name: "Send to Jira" }));

    // Then
    expect(useJiraDispatchStore.getState().activePayload).toMatchObject({
      selection: { targetId: "check-1" },
    });
  });
});
