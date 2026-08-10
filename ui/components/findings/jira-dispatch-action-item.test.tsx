import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";

import {
  ActionDropdown,
  ActionDropdownItem,
} from "@/components/shadcn/dropdown";
import { createJiraTargetSelection } from "@/lib/jira-dispatch-selection";
import { useCloudUpgradeStore, useJiraDispatchStore } from "@/store";
import { CLOUD_UPGRADE_FEATURE } from "@/types/cloud-upgrade";
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

  it("shows Cloud tooltip and opens upgrade for grouped dispatch", async () => {
    // Given
    const user = userEvent.setup();
    renderAction(["check-1"], JIRA_DISPATCH_TARGET.CHECK_ID);

    // When
    await user.click(screen.getByRole("button", { name: "Actions" }));
    const jiraAction = screen.getByRole("menuitem", { name: "Send to Jira" });
    expect(
      within(jiraAction).queryByText("Available only in Prowler Cloud"),
    ).not.toBeInTheDocument();
    await user.hover(jiraAction);

    // Then
    expect(await screen.findByRole("tooltip")).toHaveTextContent(
      "Available only in Prowler Cloud",
    );

    // When
    await user.click(jiraAction);

    // Then
    expect(useCloudUpgradeStore.getState().activeFeature).toBe(
      CLOUD_UPGRADE_FEATURE.JIRA_DISPATCH,
    );
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
