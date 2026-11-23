"use client";

import { IssueGraph } from "@/components/issues/issue-graph";
import { IssuesLoadError } from "@/components/issues/issues-load-error";
import { IssueAttributes } from "@/types/issues";

import type { IssueEvidenceState } from "./use-issue-evidence";

interface IssueAttackPathProps {
  issue: IssueAttributes;
  evidence: IssueEvidenceState;
  onRetry: () => void;
  onOpenFinding: (findingId: string) => void;
}

/** The issue's graph, or why there is none to draw yet. */
export const IssueAttackPath = ({
  issue,
  evidence,
  onRetry,
  onOpenFinding,
}: IssueAttackPathProps) => {
  if (evidence.status === "loading") {
    return (
      <p role="status" className="text-text-neutral-tertiary text-sm">
        Loading the attack path…
      </p>
    );
  }
  // Nothing to draw beats a findings error: without resources there is no
  // graph for the findings to land on.
  if (evidence.status === "loaded" && evidence.resources.length === 0) {
    return (
      <p className="text-text-neutral-tertiary text-sm">
        This issue has no affected resources to draw.
      </p>
    );
  }
  if (evidence.status === "error" || evidence.findings === undefined) {
    return (
      <IssuesLoadError
        message="Could not load the attack path for this issue."
        onRetry={onRetry}
      />
    );
  }
  return (
    <IssueGraph
      issue={issue}
      resourceUids={evidence.resources}
      findings={evidence.findings}
      onOpenFinding={onOpenFinding}
      {...(evidence.providerId && evidence.scanId
        ? { providerId: evidence.providerId, scanId: evidence.scanId }
        : { providerId: undefined, scanId: undefined })}
    />
  );
};
