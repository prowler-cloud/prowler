import { describe, expect, it } from "vitest";

import {
  buildJiraDispatchChoiceCopy,
  JIRA_SELECTION_KIND,
} from "./send-to-jira-modal-copy";

describe("buildJiraDispatchChoiceCopy", () => {
  it("uses Finding Group copy for selected Findings grouped Jira choice", () => {
    expect(
      buildJiraDispatchChoiceCopy({
        selectedCount: 2,
        isSelectedFindingGroupFlow: true,
      }),
    ).toEqual({
      description:
        "Create Jira issue(s) for 2 selected Findings from this Finding Group.",
      groupedTitle:
        "Create one Jira issue for all selected Findings in this Finding Group",
      groupedHelp:
        "Recommended. The issue will include every selected Finding from this Finding Group.",
      individualHelp:
        "Use this when each selected Finding should be tracked independently.",
    });
  });

  it("preserves resource copy for resource-based grouped Jira choice", () => {
    expect(
      buildJiraDispatchChoiceCopy({
        selectedCount: 2,
        isSelectedFindingGroupFlow: false,
      }),
    ).toEqual({
      description:
        "Create Jira issue(s) for 2 selected affected failing resources.",
      groupedTitle:
        "Create one Jira issue for all selected affected failing resources",
      groupedHelp:
        "Recommended. The issue will include every selected resource from this finding group.",
      individualHelp:
        "Use this when each selected resource should be tracked independently.",
    });
  });

  it("uses neutral Findings copy outside a single Finding Group", () => {
    expect(
      buildJiraDispatchChoiceCopy({
        selectedCount: 2,
        isSelectedFindingGroupFlow: false,
        selectionKind: JIRA_SELECTION_KIND.FINDINGS,
      }),
    ).toEqual({
      description: "Create Jira issue(s) for 2 selected Findings.",
      groupedTitle: "Create one Jira issue for all selected Findings",
      groupedHelp:
        "Recommended. The issue will include every selected Finding.",
      individualHelp:
        "Use this when each selected Finding should be tracked independently.",
    });
  });
});
