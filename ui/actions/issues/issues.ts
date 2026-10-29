"use server";

import { apiBaseUrl, getAuthHeaders } from "@/lib";
import { handleApiError, handleApiResponse } from "@/lib/server-actions-helper";
import {
  ISSUE_FINDINGS_LIMIT,
  IssueDetailResponse,
  IssueFinding,
  IssueResponse,
  IssuesOverviewResponse,
  IssueTriageNote,
} from "@/types/issues";

import { toIssueFindings, toIssueTriageNotes } from "./issues.adapter";
import {
  ISSUE_TRIAGE_WRITE_METHOD,
  type IssueTriageWriteMethod,
  type IssueWriteResult,
  type UpdateIssueTriageInput,
} from "./types";

const withFilters = (
  url: URL,
  filters: Record<string, string | string[] | undefined>,
) => {
  Object.entries(filters).forEach(([key, value]) => {
    if (key === "filter[search]" || value === undefined) return;
    // `__in` filters take one comma-separated value (filter[verdict__in]=a,b);
    // a repeated param would keep only the last value.
    url.searchParams.set(key, Array.isArray(value) ? value.join(",") : value);
  });
};

export const getIssuesOverview = async ({
  filters = {},
}: {
  filters?: Record<string, string | string[] | undefined>;
} = {}): Promise<IssuesOverviewResponse | undefined> => {
  const headers = await getAuthHeaders({ contentType: false });
  const url = new URL(`${apiBaseUrl}/issues/overview`);
  withFilters(url, filters);

  try {
    const response = await fetch(url.toString(), { headers });
    return await handleApiResponse(response);
  } catch (error) {
    console.error("Error fetching issue verdict summary:", error);
    return undefined;
  }
};

export const getIssues = async ({
  filters = {},
  page = 1,
  pageSize = 10,
  sort,
}: {
  filters?: Record<string, string | string[] | undefined>;
  page?: number;
  pageSize?: number;
  /**
   * Omitted by default on purpose. The API already orders worst verdict
   * first, and restating it here meant the two could disagree — which they
   * did: a stale `sort=verdict` became invalid when ordering moved to
   * `verdict_rank`, and the list silently came back empty while the counts
   * beside it still rendered.
   */
  sort?: string;
} = {}): Promise<IssueResponse | undefined> => {
  const headers = await getAuthHeaders({ contentType: false });
  const url = new URL(`${apiBaseUrl}/issues`);
  url.searchParams.append("page[number]", String(page));
  url.searchParams.append("page[size]", String(pageSize));
  if (sort) url.searchParams.append("sort", sort);
  withFilters(url, filters);

  try {
    const response = await fetch(url.toString(), { headers });
    return await handleApiResponse(response);
  } catch (error) {
    console.error("Error fetching issues:", error);
    return undefined;
  }
};

export const getIssue = async (
  id: string,
): Promise<IssueDetailResponse | undefined> => {
  const headers = await getAuthHeaders({ contentType: false });
  const url = new URL(`${apiBaseUrl}/issues/${encodeURIComponent(id)}`);

  try {
    const response = await fetch(url.toString(), { headers });
    return await handleApiResponse(response);
  } catch (error) {
    console.error("Error fetching issue:", error);
    return undefined;
  }
};

/** Load a bounded preview from the issue's exact scan, including every resource association. */
export const getIssueFindings = async (
  scanId: string,
  findingUids: string[],
): Promise<IssueFinding[] | undefined> => {
  if (!scanId) return undefined;
  const uids = Array.from(new Set(findingUids)).slice(0, ISSUE_FINDINGS_LIMIT);
  if (uids.length === 0) return [];

  const headers = await getAuthHeaders({ contentType: false });
  const url = new URL(`${apiBaseUrl}/findings`);
  url.searchParams.set("filter[scan]", scanId);
  url.searchParams.set("filter[uid__in]", uids.join(","));
  url.searchParams.set("include", "resources");
  url.searchParams.set(
    "fields[findings]",
    "uid,check_id,severity,check_metadata,triage_status,resources",
  );
  url.searchParams.set("fields[resources]", "uid");
  url.searchParams.set("page[size]", String(uids.length));

  try {
    const response = await fetch(url.toString(), { headers });
    return toIssueFindings(await handleApiResponse(response));
  } catch (error) {
    console.error("Error fetching issue findings:", error);
    return undefined;
  }
};

/** Write one issue triage request; any non-2xx comes back as an error to show, with its status. */
const writeIssueTriage = async (
  path: string,
  method: IssueTriageWriteMethod,
  data: Record<string, unknown>,
): Promise<IssueWriteResult> => {
  try {
    const headers = await getAuthHeaders({ contentType: true });
    const response = await fetch(`${apiBaseUrl}${path}`, {
      method,
      headers,
      body: JSON.stringify({ data }),
    });
    // The list shows each issue's triage status.
    const result = await handleApiResponse(response, "/issues");
    return result?.error
      ? { error: result.error, status: result.status }
      : { success: true };
  } catch (error) {
    return handleApiError(error);
  }
};

/** Set the status of the path an issue describes, with an optional note. */
export const updateIssueTriage = async (
  id: string,
  { status, note }: UpdateIssueTriageInput,
): Promise<IssueWriteResult> =>
  writeIssueTriage(
    `/issues/${encodeURIComponent(id)}/triage`,
    ISSUE_TRIAGE_WRITE_METHOD.UPDATE,
    {
      type: "issue-triages",
      attributes: { status, ...(note ? { note } : {}) },
    },
  );

/** Add a note to an issue's triage without changing its status. */
export const addIssueNote = async (
  id: string,
  body: string,
): Promise<IssueWriteResult> =>
  writeIssueTriage(
    `/issues/${encodeURIComponent(id)}/triage/notes`,
    ISSUE_TRIAGE_WRITE_METHOD.ADD_NOTE,
    {
      type: "issue-triage-notes",
      attributes: { body },
    },
  );

export const getIssueNotes = async (
  id: string,
): Promise<IssueTriageNote[] | undefined> => {
  const headers = await getAuthHeaders({ contentType: false });
  const url = new URL(
    `${apiBaseUrl}/issues/${encodeURIComponent(id)}/triage/notes`,
  );
  url.searchParams.set("include", "created_by");
  // shortcut: newest 100 notes only (the API's max page size; its default is 10), page through links.next once an issue's history outgrows it
  url.searchParams.set("page[size]", "100");

  try {
    const response = await fetch(url.toString(), { headers });
    return toIssueTriageNotes(await handleApiResponse(response));
  } catch (error) {
    console.error("Error fetching issue notes:", error);
    return undefined;
  }
};
