"use server";

import { z } from "zod";

import { apiBaseUrl, getAuthHeaders } from "@/lib";
import type { JiraIssueLinksResult } from "@/types/integrations";

import { adaptJiraIssues } from "./jira-issues.adapter";
import type { JiraIssuesResponse } from "./jira-issues.types";

const REQUEST_TIMEOUT_MS = 10_000;
// One request covers a drawer (1 uid) or a page of findings; the API caps the
// page size, so larger batches are split by the caller.
const MAX_FINDING_UIDS_PER_REQUEST = 100;

const jiraIssuesQuerySchema = z.object({
  findingUids: z
    .array(z.string().trim().min(1))
    .min(1)
    .max(MAX_FINDING_UIDS_PER_REQUEST),
  providerId: z.string().uuid().optional(),
});

export type JiraIssuesQuery = z.infer<typeof jiraIssuesQuerySchema>;

/**
 * Jira issues linked to the given findings, keyed by finding UID.
 *
 * Never throws: an older API without the endpoint, a network error or a
 * timeout all resolve to `unavailable: true` so callers can render nothing.
 */
export const getJiraIssuesForFindings = async (
  query: JiraIssuesQuery,
): Promise<JiraIssueLinksResult> => {
  const parsed = jiraIssuesQuerySchema.safeParse(query);
  if (!parsed.success) {
    return { issues: [], unavailable: false };
  }

  const { findingUids, providerId } = parsed.data;
  const uniqueUids = Array.from(new Set(findingUids));

  try {
    const headers = await getAuthHeaders({ contentType: false });
    const url = new URL(`${apiBaseUrl}/jira-issues`);
    url.searchParams.set("filter[finding_uid__in]", uniqueUids.join(","));
    if (providerId) {
      url.searchParams.set("filter[provider_id]", providerId);
    }
    url.searchParams.set("page[size]", String(uniqueUids.length));

    const response = await fetch(url.toString(), {
      headers,
      signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
    });
    if (!response.ok) {
      return { issues: [], unavailable: true };
    }

    const body = (await response.json()) as JiraIssuesResponse;
    return { issues: adaptJiraIssues(body), unavailable: false };
  } catch (error) {
    console.error("Error fetching the Jira issues linked to findings:", error);
    return { issues: [], unavailable: true };
  }
};
