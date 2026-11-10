"use server";

import { ISSUE_FINDINGS_LIMIT } from "@/types/issues";

import { getIssue, getIssueFindings } from "./issues";
import type { IssueEvidence } from "./types";

/** Resolves the finding UIDs here: sent from the browser, they can exceed the edge's 8 KB body limit. */
export const getIssueEvidence = async (
  id: string,
  fallbackScanId?: string,
): Promise<IssueEvidence | undefined> => {
  const detail = await getIssue(id);
  const attributes = detail?.data?.attributes;
  if (!detail || !attributes?.resource_uids) return undefined;

  const relationships = detail.data.relationships;
  const scanId = relationships?.scan?.data?.id ?? fallbackScanId;
  const findingUids = attributes.finding_uids ?? [];
  const findings = scanId
    ? await getIssueFindings(scanId, findingUids)
    : findingUids.length === 0
      ? []
      : undefined;

  return {
    resources: attributes.resource_uids,
    findings,
    findingsTruncated: new Set(findingUids).size > ISSUE_FINDINGS_LIMIT,
    scanId,
    providerId: relationships?.provider?.data?.id,
  };
};
