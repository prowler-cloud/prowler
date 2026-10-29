"use client";

import { IssueGraph } from "@/components/issues/issue-graph";
import { IssuesLoadError } from "@/components/issues/issues-load-error";
import { useIssueEvidence } from "@/hooks/use-issue-evidence";
import { IssueAttributes } from "@/types/issues";

interface IssueAttackPathProps {
  id: string;
  issue: IssueAttributes;
  scanId?: string;
  providerId?: string;
}

/** The issue's graph for the side panel; findings open on the full page. */
export const IssueAttackPath = ({
  id,
  issue,
  scanId,
  providerId,
}: IssueAttackPathProps) => {
  const { state, retry } = useIssueEvidence(id, scanId, providerId);

  if (state.status === "loading") {
    return (
      <p role="status" className="text-text-neutral-tertiary text-sm">
        Loading the attack path…
      </p>
    );
  }
  // Nothing to draw beats a findings error: without resources there is no
  // graph for the findings to land on.
  if (state.status === "loaded" && state.resources.length === 0) {
    return (
      <p className="text-text-neutral-tertiary text-sm">
        This issue has no affected resources to draw.
      </p>
    );
  }
  if (state.status === "error" || state.findings === undefined) {
    return (
      <IssuesLoadError
        message="Could not load the attack path for this issue."
        onRetry={retry}
      />
    );
  }
  return (
    <IssueGraph
      issue={issue}
      resourceUids={state.resources}
      findings={state.findings}
      readOnly
      {...(state.providerId && state.scanId
        ? { providerId: state.providerId, scanId: state.scanId }
        : { providerId: undefined, scanId: undefined })}
    />
  );
};
