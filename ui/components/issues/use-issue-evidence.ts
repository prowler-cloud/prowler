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
    // A failed background refresh keeps what is already shown; only a first
    // load or a retry (which resets to loading) surfaces the error.
    const fail = () =>
      setState((previous) =>
        previous.status === "loaded" ? previous : { status: "error" },
      );
    getIssue(id)
      .then(async (detail) => {
        if (cancelled) return;
        const attributes = detail?.data?.attributes;
        if (!attributes?.resource_uids) {
          fail();
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
        if (cancelled) return;
        setState((previous) => {
          // A refresh that loses the findings keeps the ones already shown,
          // as long as they belong to the same scan; resources and provider
          // always take the fresh answer.
          const keepFindings =
            findings === undefined &&
            previous.status === "loaded" &&
            previous.findings !== undefined &&
            previous.scanId === detailScanId;
          return {
            status: "loaded",
            resources: attributes.resource_uids,
            findings: keepFindings ? previous.findings : findings,
            findingsTruncated: keepFindings
              ? previous.findingsTruncated
              : new Set(findingUids).size > ISSUE_FINDINGS_LIMIT,
            scanId: detailScanId,
            providerId: detailProviderId,
          };
        });
      })
      .catch(() => {
        if (!cancelled) fail();
      });
    return () => {
      cancelled = true;
    };
  }, [id, scanId, providerId, attempt]);

  const retry = () => {
    setState({ status: "loading" });
    setAttempt((value) => value + 1);
  };

  /** Reloads in the background: what is shown stays until the answer lands. */
  const refresh = () => setAttempt((value) => value + 1);

  return { state, retry, refresh };
};
