"use client";

import { useEffect, useState } from "react";

import { getIssue, getIssueFindings } from "@/actions/issues";
import { ISSUE_FINDINGS_LIMIT, IssueFinding } from "@/types/issues";

export type IssueEvidenceState =
  | { status: "loading" }
  | { status: "error" }
  | {
      status: "loaded";
      resources: string[];
      findings: IssueFinding[] | undefined;
      /** `getIssueFindings` capped the preview at ISSUE_FINDINGS_LIMIT. */
      findingsTruncated: boolean;
      scanId?: string;
      providerId?: string;
    };

/**
 * The issue's resources and findings. Only the detail endpoint carries the
 * resource uids, so this fetches it, then the findings of the issue's scan.
 */
export const useIssueEvidence = (
  id: string,
  scanId?: string,
  providerId?: string,
) => {
  const [attempt, setAttempt] = useState(0);
  const [state, setState] = useState<IssueEvidenceState>({
    status: "loading",
  });

  useEffect(() => {
    let cancelled = false;
    getIssue(id)
      .then(async (detail) => {
        if (cancelled) return;
        const attributes = detail?.data?.attributes;
        if (!attributes?.resource_uids) {
          setState({ status: "error" });
          return;
        }
        const detailScanId =
          detail?.data.relationships?.scan?.data?.id ?? scanId;
        const detailProviderId =
          detail?.data.relationships?.provider?.data?.id ?? providerId;
        const findingUids = attributes.finding_uids ?? [];
        const findings = detailScanId
          ? await getIssueFindings(detailScanId, findingUids)
          : findingUids.length === 0
            ? []
            : undefined;
        if (!cancelled)
          setState({
            status: "loaded",
            resources: attributes.resource_uids,
            findings,
            findingsTruncated: new Set(findingUids).size > ISSUE_FINDINGS_LIMIT,
            scanId: detailScanId,
            providerId: detailProviderId,
          });
      })
      .catch(() => {
        if (!cancelled) setState({ status: "error" });
      });
    return () => {
      cancelled = true;
    };
  }, [id, scanId, providerId, attempt]);

  const retry = () => {
    setState({ status: "loading" });
    setAttempt((value) => value + 1);
  };

  return { state, retry };
};
