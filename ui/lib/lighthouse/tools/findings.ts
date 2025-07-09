import { tool } from "@langchain/core/tools";
import { z } from "zod";

import { getMetadataInfo } from "@/actions/findings";
import {
  getLighthouseFindings,
  getLighthouseLatestFindings,
} from "@/actions/lighthouse/findings";
import { getFindingsSchema, getMetadataInfoSchema } from "@/types/lighthouse";

export const getFindingsTool = tool(
  async ({ page, pageSize, query, sort, filters }) => {
    return await getLighthouseFindings({
      page,
      pageSize,
      query,
      sort,
      filters,
    });
  },
  {
    name: "getFindings",
    description:
      "Retrieves a list of all findings with options for filtering by various criteria.",
    schema: getFindingsSchema,
  },
);

export const getLatestFindingsTool = tool(
  async ({ page, pageSize, query, sort, filters }) => {
    return await getLighthouseLatestFindings({
      page,
      pageSize,
      query,
      sort,
      filters,
    });
  },
  {
    name: "getLatestFindings",
    description:
      "Retrieves a list of the latest findings from the latest scans of all providers with options for filtering by various criteria.",
    // getLatestFindings uses the same schema as getFindings
    schema: getFindingsSchema,
  },
);

// Function to get a summary of new and changed failed findings that appeared in a particular scan
export const getNewFailedFindingsSummary = async (scanId: string) => {
  let allFindings: any[] = [];
  let currentPage = 1;
  let totalPages = 1;
  const pageSize = 100;

  do {
    const response = await getLighthouseFindings({
      page: currentPage,
      pageSize: pageSize,
      sort: "severity",
      filters: {
        "fields[findings]": "check_id,severity",
        "filter[scan]": scanId,
        "filter[status]": "FAIL",
        "filter[muted]": "false",
        "filter[delta__in]": "new,changed",
      },
    });

    if (response?.data) {
      allFindings = allFindings.concat(response.data);
    }

    if (currentPage === 1 && response?.meta?.pagination) {
      totalPages = response.meta.pagination.pages;
    }

    currentPage++;
  } while (currentPage <= totalPages);

  const summary: Record<
    string,
    Record<string, { count: number; finding_ids: string[] }>
  > = {};

  allFindings.forEach((finding) => {
    const severity = finding.attributes.severity;
    const checkId = finding.attributes.check_id;
    const findingId = finding.id;

    // Initialize severity group if it doesn't exist
    if (!summary[severity]) {
      summary[severity] = {};
    }

    // Initialize check_id group if it doesn't exist
    if (!summary[severity][checkId]) {
      summary[severity][checkId] = {
        count: 0,
        finding_ids: [],
      };
    }

    // Add finding to the appropriate group
    summary[severity][checkId].count++;
    summary[severity][checkId].finding_ids.push(findingId);
  });

  return summary;
};

export const getNewFailedFindingsSummaryTool = tool(
  async ({ scanId }) => {
    return await getNewFailedFindingsSummary(scanId);
  },
  {
    name: "getNewFailedFindingsSummary",
    description:
      "Fetches summary of new and changed failed findings that appeared in a particular scan. Summary includes count of findings by severity, check_id and finding_ids.",
    schema: z.object({
      scanId: z
        .string()
        .describe("The UUID of the scan to fetch failed findings summary for."),
    }),
  },
);

export const getMetadataInfoTool = tool(
  async ({ query, sort, filters }) => {
    return await getMetadataInfo({ query, sort, filters });
  },
  {
    name: "getMetadataInfo",
    description:
      "Fetches unique metadata values from a set of findings. This is useful for dynamic filtering.",
    schema: getMetadataInfoSchema,
  },
);
