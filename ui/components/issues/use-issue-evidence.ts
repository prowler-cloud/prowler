"use client";

import { useEffect, useState } from "react";

import { getIssueEvidence } from "@/actions/issues";
import { IssueFinding } from "@/types/issues";

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

/** The issue's resources and findings, read from its detail and its scan. */
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
    getIssueEvidence(id, scanId)
      .then((evidence) => {
        if (cancelled) return;
        if (!evidence) {
          fail();
          return;
        }
        setState((previous) => {
          // A refresh that loses the findings keeps the ones already shown,
          // as long as they belong to the same scan; resources and provider
          // always take the fresh answer.
          const keepFindings =
            evidence.findings === undefined &&
            previous.status === "loaded" &&
            previous.findings !== undefined &&
            previous.scanId === evidence.scanId;
          return {
            status: "loaded",
            resources: evidence.resources,
            findings: keepFindings ? previous.findings : evidence.findings,
            findingsTruncated: keepFindings
              ? previous.findingsTruncated
              : evidence.findingsTruncated,
            scanId: evidence.scanId,
            providerId: evidence.providerId ?? providerId,
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
