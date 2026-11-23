import { beforeEach, describe, expect, it, vi } from "vitest";

import { ISSUE_FINDINGS_LIMIT, type IssueFinding } from "@/types/issues";

const { getIssue, getIssueFindings } = vi.hoisted(() => ({
  getIssue: vi.fn(),
  getIssueFindings: vi.fn(),
}));

vi.mock("./issues", () => ({ getIssue, getIssueFindings }));

import { getIssueEvidence } from "./issue-evidence";

const finding: IssueFinding = {
  id: "finding-1",
  uid: "uid-0",
  checkId: "iam_role_cross_account_readonlyaccess_policy",
  checkTitle: "Role trusts another account",
  severity: "high",
  triageStatus: "open",
  resourceUid: "role",
};

const detail = ({
  scanId,
  providerId,
  findingUids = [],
  resourceUids = ["role"],
}: {
  scanId?: string;
  providerId?: string;
  findingUids?: string[];
  resourceUids?: string[] | null;
}) => ({
  data: {
    attributes: { resource_uids: resourceUids, finding_uids: findingUids },
    relationships: {
      ...(scanId && { scan: { data: { type: "scans", id: scanId } } }),
      ...(providerId && {
        provider: { data: { type: "providers", id: providerId } },
      }),
    },
  },
});

describe("getIssueEvidence", () => {
  beforeEach(() => {
    getIssue.mockReset();
    getIssueFindings.mockReset().mockResolvedValue([finding]);
  });

  it("reads the finding UIDs on the server, so the browser only sends the issue id", async () => {
    // Given an issue with more findings than one request may carry
    const findingUids = Array.from({ length: 300 }, (_, i) => `uid-${i}`);
    getIssue.mockResolvedValue(
      detail({ scanId: "scan-1", providerId: "provider-1", findingUids }),
    );

    // When
    const evidence = await getIssueEvidence("issue-1");

    // Then
    expect(getIssue).toHaveBeenCalledWith("issue-1");
    expect(getIssueFindings).toHaveBeenCalledWith("scan-1", findingUids);
    expect(evidence).toEqual({
      resources: ["role"],
      findings: [finding],
      findingsTruncated: findingUids.length > ISSUE_FINDINGS_LIMIT,
      scanId: "scan-1",
      providerId: "provider-1",
    });
  });

  it("falls back to the list row's scan when the detail names none", async () => {
    getIssue.mockResolvedValue(detail({ findingUids: ["uid-0"] }));

    const evidence = await getIssueEvidence("issue-1", "row-scan");

    expect(getIssueFindings).toHaveBeenCalledWith("row-scan", ["uid-0"]);
    expect(evidence?.scanId).toBe("row-scan");
    expect(evidence?.providerId).toBeUndefined();
  });

  it("tells an issue without findings apart from findings it cannot load", async () => {
    getIssue.mockResolvedValue(detail({}));
    await expect(getIssueEvidence("issue-1")).resolves.toMatchObject({
      findings: [],
    });

    getIssue.mockResolvedValue(detail({ findingUids: ["uid-0"] }));
    await expect(getIssueEvidence("issue-1")).resolves.toMatchObject({
      findings: undefined,
    });
    expect(getIssueFindings).not.toHaveBeenCalled();
  });

  it("fails when the detail does not load or carries no resources", async () => {
    getIssue.mockResolvedValueOnce(undefined);
    await expect(getIssueEvidence("issue-1")).resolves.toBeUndefined();

    getIssue.mockResolvedValueOnce(detail({ resourceUids: null }));
    await expect(getIssueEvidence("issue-1")).resolves.toBeUndefined();
  });
});
