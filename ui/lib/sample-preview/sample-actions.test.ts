import { beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("next/cache", () => ({ revalidatePath: vi.fn() }));
// Sample answers return before any auth header is built.
vi.mock("@/auth.config", () => ({ auth: vi.fn() }));

import {
  adaptFindingGroupResourcesResponse,
  getFindingGroupResources,
} from "@/actions/finding-groups";
import {
  adaptFindingsByResourceResponse,
  getFindingById,
  getLatestFindingsByResourceUid,
} from "@/actions/findings";
import { getFindingComplianceFrameworks } from "@/actions/findings/finding-compliance-frameworks";
import { updateFindingTriage } from "@/actions/findings/findings-triage";
import { sendJiraDispatch } from "@/actions/integrations/jira-dispatch";
import {
  addIssueNote,
  getIssue,
  getIssueFindings,
  getIssueNotes,
  updateIssueTriage,
} from "@/actions/issues";
import { createMuteRule } from "@/actions/mute-rules";
import { getResourceEvents } from "@/actions/resources";
import { createPartialScan } from "@/actions/scans";
import { FINDING_TRIAGE_STATUS } from "@/types/findings-triage";

import { SAMPLE_ACCOUNT, SAMPLE_CHECKS } from "./sample-dataset";
import { SAMPLE_ISSUES } from "./sample-issues";
import { SAMPLE_COMPLIANCE_WATCHLIST_RESPONSE } from "./sample-overview";
import { SAMPLE_WRITE_MESSAGE } from "./sample-records";

// The sample drill-downs run the real actions and adapters; none may reach the API.
const fetchMock = vi.fn();

const SAMPLE_SCAN_FILTERS = { "filter[scan]": SAMPLE_ACCOUNT.scanId };
const PUBLIC_BUCKETS = SAMPLE_CHECKS.find(
  (check) => check.checkId === "s3_bucket_public_access",
)!;

const groupRows = async (page = 1) =>
  adaptFindingGroupResourcesResponse(
    await getFindingGroupResources({
      checkId: PUBLIC_BUCKETS.checkId,
      page,
      pageSize: 10,
      filters: SAMPLE_SCAN_FILTERS,
    }),
    PUBLIC_BUCKETS.checkId,
  );

describe("sample drill-downs", () => {
  beforeEach(() => {
    fetchMock.mockReset();
    vi.stubGlobal("fetch", fetchMock);
  });

  it("expands a finding group into its resources, failed first, without the API", async () => {
    const rows = await groupRows();
    const lastPage = await groupRows(3);

    expect(rows).toHaveLength(10);
    expect(
      rows.slice(0, PUBLIC_BUCKETS.failed).map((row) => row.status),
    ).toEqual(Array(PUBLIC_BUCKETS.failed).fill("FAIL"));
    expect(rows[PUBLIC_BUCKETS.failed].status).toBe("PASS");
    expect(rows[0]).toMatchObject({
      resourceName: "acme-customer-exports",
      providerAlias: SAMPLE_ACCOUNT.alias,
      statusExtended:
        "S3 Bucket acme-customer-exports has a bucket policy that allows public access.",
    });
    // 24 buckets: pages of 10, 10 and 4.
    expect(lastPage).toHaveLength(
      PUBLIC_BUCKETS.failed + PUBLIC_BUCKETS.passed - 20,
    );
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("opens a group resource in the drawer with its check details and frameworks", async () => {
    const [row] = await groupRows();

    const [finding] = adaptFindingsByResourceResponse(
      await getFindingById(row.findingId, "resources,scan.provider"),
    );
    const otherFindings = adaptFindingsByResourceResponse(
      await getLatestFindingsByResourceUid({
        resourceUid: row.resourceUid,
        sample: true,
      }),
    );

    expect(finding).toMatchObject({
      id: row.findingId,
      checkTitle: PUBLIC_BUCKETS.title,
      resourceName: "acme-customer-exports",
      providerAlias: SAMPLE_ACCOUNT.alias,
      providerUid: SAMPLE_ACCOUNT.uid,
      scan: expect.objectContaining({ state: "completed" }),
    });
    expect(finding.risk).not.toBe("");
    expect(finding.remediation.code.cli).toContain("acme-customer-exports");
    expect(finding.complianceFrameworks).toContain("CIS");
    // The same bucket also fails the secure transport check.
    expect(otherFindings.map((other) => other.checkId)).toEqual(
      expect.arrayContaining([
        "s3_bucket_public_access",
        "s3_bucket_secure_transport_policy",
      ]),
    );
    const { frameworks } = await getFindingComplianceFrameworks(row.findingId, {
      inWatchlist: true,
    });
    // The same frameworks the Overview watchlist and Compliance page show.
    expect(frameworks.map((framework) => framework.complianceId)).toEqual(
      expect.arrayContaining(
        SAMPLE_COMPLIANCE_WATCHLIST_RESPONSE.data.map(
          (item) => item.attributes.compliance_id,
        ),
      ),
    );
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("shows the CloudTrail history of a sample resource in the Events tab", async () => {
    const [row] = await groupRows();
    const [finding] = adaptFindingsByResourceResponse(
      await getFindingById(row.findingId, "resources,scan.provider"),
    );

    const events = await getResourceEvents(finding.resourceId);

    expect(
      events.data?.map(
        (event: { attributes: { event_name: string } }) =>
          event.attributes.event_name,
      ),
    ).toEqual(["PutBucketPolicy", "CreateBucket"]);
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("marks sample findings read-only, with the reason the triage control shows", async () => {
    const [row] = await groupRows();

    expect(row.triage).toMatchObject({
      status: FINDING_TRIAGE_STATUS.OPEN,
      canEdit: false,
      disabledReason: "sample",
    });
  });

  it("opens every sample issue with exactly the findings it counts", async () => {
    for (const issue of SAMPLE_ISSUES) {
      const detail = await getIssue(issue.id);
      const scanId = detail?.data.relationships?.scan?.data?.id ?? "";
      const findings = await getIssueFindings(
        scanId,
        detail?.data.attributes.finding_uids ?? [],
      );

      expect(findings).toHaveLength(issue.attributes.findings_count);
      expect(new Set(detail?.data.attributes.resource_uids)).toEqual(
        new Set(findings?.map((finding) => finding.resourceUid)),
      );
      await expect(getIssueNotes(issue.id)).resolves.toEqual([]);
    }
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("refuses writes on sample data with a message to connect an account", async () => {
    const [issue] = SAMPLE_ISSUES;
    const [row] = await groupRows();
    const muteForm = new FormData();
    muteForm.set("name", "Sample mute");
    muteForm.set("reason", "Trying it out");
    muteForm.set("finding_ids", JSON.stringify([row.findingId]));

    await expect(
      updateIssueTriage(issue.id, {
        status: FINDING_TRIAGE_STATUS.UNDER_REVIEW,
      }),
    ).resolves.toEqual({ error: SAMPLE_WRITE_MESSAGE });
    await expect(addIssueNote(issue.id, "A note")).resolves.toEqual({
      error: SAMPLE_WRITE_MESSAGE,
    });
    await expect(createMuteRule(null, muteForm)).resolves.toEqual({
      errors: { general: SAMPLE_WRITE_MESSAGE },
    });
    await expect(
      sendJiraDispatch({
        integrationId: "jira-1",
        filter: "finding_id",
        projectKey: "DEMO",
        issueType: "Task",
        targetIds: ["real-finding", row.findingId],
      }),
    ).resolves.toEqual({ success: false, error: SAMPLE_WRITE_MESSAGE });
    await expect(
      createPartialScan({
        providerId: SAMPLE_ACCOUNT.providerId,
        resourceUids: [row.resourceUid],
      }),
    ).resolves.toEqual({ error: SAMPLE_WRITE_MESSAGE });
    await expect(
      updateFindingTriage({
        findingId: row.findingId,
        findingUid: row.findingId,
        triageId: null,
        notesCount: 0,
        status: FINDING_TRIAGE_STATUS.UNDER_REVIEW,
      }),
    ).rejects.toThrow(SAMPLE_WRITE_MESSAGE);
    expect(fetchMock).not.toHaveBeenCalled();
  });
});
