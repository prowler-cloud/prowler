export const JIRA_SELECTION_KIND = {
  FINDINGS: "findings",
  RESOURCES: "resources",
} as const;

type JiraSelectionKind =
  (typeof JIRA_SELECTION_KIND)[keyof typeof JIRA_SELECTION_KIND];

interface JiraDispatchChoiceCopyParams {
  selectedCount: number;
  isSelectedFindingGroupFlow: boolean;
  selectionKind?: JiraSelectionKind;
}

interface JiraDispatchChoiceCopy {
  description: string;
  groupedTitle: string;
  groupedHelp: string;
  individualHelp: string;
}

export const buildJiraDispatchChoiceCopy = ({
  selectedCount,
  isSelectedFindingGroupFlow,
  selectionKind = JIRA_SELECTION_KIND.RESOURCES,
}: JiraDispatchChoiceCopyParams): JiraDispatchChoiceCopy => {
  if (isSelectedFindingGroupFlow) {
    return {
      description: `Create Jira issue(s) for ${selectedCount} selected Findings from this Finding Group.`,
      groupedTitle:
        "Create one Jira issue for all selected Findings in this Finding Group",
      groupedHelp:
        "Recommended. The issue will include every selected Finding from this Finding Group.",
      individualHelp:
        "Use this when each selected Finding should be tracked independently.",
    };
  }

  if (selectionKind === JIRA_SELECTION_KIND.FINDINGS) {
    return {
      description: `Create Jira issue(s) for ${selectedCount} selected Findings.`,
      groupedTitle: "Create one Jira issue for all selected Findings",
      groupedHelp:
        "Recommended. The issue will include every selected Finding.",
      individualHelp:
        "Use this when each selected Finding should be tracked independently.",
    };
  }

  return {
    description: `Create Jira issue(s) for ${selectedCount} selected affected failing resources.`,
    groupedTitle:
      "Create one Jira issue for all selected affected failing resources",
    groupedHelp:
      "Recommended. The issue will include every selected resource from this finding group.",
    individualHelp:
      "Use this when each selected resource should be tracked independently.",
  };
};
