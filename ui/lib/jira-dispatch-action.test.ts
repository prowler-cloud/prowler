import { describe, expect, it } from "vitest";

import {
  createJiraBatchSelection,
  createJiraTargetSelection,
} from "@/lib/jira-dispatch-selection";
import { JIRA_DISPATCH_MODE, JIRA_DISPATCH_TARGET } from "@/types/integrations";

import {
  buildJiraActionLabel,
  getJiraDispatchActionState,
} from "./jira-dispatch-action";

describe("getJiraDispatchActionState", () => {
  it("allows one Finding without grouped dispatch", () => {
    // Given
    const selection = createJiraTargetSelection(
      ["finding-1"],
      JIRA_DISPATCH_TARGET.FINDING_ID,
    )!;

    // When
    const state = getJiraDispatchActionState({ selection }, false);

    // Then
    expect(state).toEqual({
      canChooseGroupedDispatch: false,
      defaultDispatchMode: JIRA_DISPATCH_MODE.INDIVIDUAL,
      requiresUpgrade: false,
    });
  });

  it("offers grouped choice for multiple Findings in Cloud", () => {
    // Given
    const selection = createJiraTargetSelection(
      ["finding-1", "finding-2"],
      JIRA_DISPATCH_TARGET.FINDING_ID,
    )!;

    // When
    const state = getJiraDispatchActionState({ selection }, true);

    // Then
    expect(state).toEqual({
      canChooseGroupedDispatch: true,
      defaultDispatchMode: JIRA_DISPATCH_MODE.GROUPED,
      requiresUpgrade: false,
    });
  });

  it("requires upgrade for multiple Findings outside Cloud", () => {
    // Given
    const selection = createJiraTargetSelection(
      ["finding-1", "finding-2"],
      JIRA_DISPATCH_TARGET.FINDING_ID,
    )!;

    // When
    const state = getJiraDispatchActionState({ selection }, false);

    // Then
    expect(state.requiresUpgrade).toBe(true);
    expect(state.canChooseGroupedDispatch).toBe(false);
  });

  it("offers grouped choice for one Finding Group with multiple resources", () => {
    // Given
    const selection = createJiraTargetSelection(
      ["check-1"],
      JIRA_DISPATCH_TARGET.CHECK_ID,
    )!;

    // When
    const state = getJiraDispatchActionState(
      { selection, selectedResourceCount: 2 },
      true,
    );

    // Then
    expect(state).toEqual({
      canChooseGroupedDispatch: true,
      defaultDispatchMode: JIRA_DISPATCH_MODE.GROUPED,
      requiresUpgrade: false,
    });
  });

  it("keeps mixed batches grouped without offering one global choice", () => {
    // Given
    const selection = createJiraBatchSelection([
      {
        targetIds: ["check-1"],
        targetType: JIRA_DISPATCH_TARGET.CHECK_ID,
        dispatchMode: JIRA_DISPATCH_MODE.GROUPED,
      },
      {
        targetIds: ["finding-1"],
        targetType: JIRA_DISPATCH_TARGET.FINDING_ID,
        dispatchMode: JIRA_DISPATCH_MODE.INDIVIDUAL,
      },
    ])!;

    // When
    const state = getJiraDispatchActionState({ selection }, true);

    // Then
    expect(state.defaultDispatchMode).toBe(JIRA_DISPATCH_MODE.GROUPED);
    expect(state.canChooseGroupedDispatch).toBe(false);
  });
});

describe("buildJiraActionLabel", () => {
  it.each([
    [{ findingCount: 1 }, "Send 1 Finding to Jira"],
    [{ findingCount: 2 }, "Send 2 Findings to Jira"],
    [{ findingGroupCount: 1 }, "Send 1 Finding Group to Jira"],
    [
      { findingGroupCount: 2, findingCount: 1 },
      "Send 2 Finding Groups and 1 Finding to Jira",
    ],
  ])("builds consistent Jira action copy", (counts, expected) => {
    // Given / When
    const label = buildJiraActionLabel(counts);

    // Then
    expect(label).toBe(expected);
  });
});
