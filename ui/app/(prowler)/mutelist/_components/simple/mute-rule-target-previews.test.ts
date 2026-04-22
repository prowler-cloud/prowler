import { describe, expect, it, vi } from "vitest";

const { getLatestFindingsMock, adaptFindingsByResourceResponseMock } =
  vi.hoisted(() => ({
  getLatestFindingsMock: vi.fn(),
  adaptFindingsByResourceResponseMock: vi.fn(),
}));

vi.mock("@/actions/findings", () => ({
  getLatestFindings: getLatestFindingsMock,
  adaptFindingsByResourceResponse: adaptFindingsByResourceResponseMock,
}));

import {
  formatMuteRuleTargetPreview,
  hydrateMuteRuleTargetPreviews,
} from "./mute-rule-target-previews";

function makeFinding(
  overrides?: Partial<{
    uid: string;
    checkTitle: string;
    checkId: string;
    resourceName: string;
    resourceUid: string;
  }>,
) {
  return {
    uid: "uid-1",
    checkTitle: "S3 Bucket Public Access",
    checkId: "s3_bucket_public_access",
    resourceName: "bucket-a",
    resourceUid: "arn:aws:s3:::bucket-a",
    ...overrides,
  };
}

describe("mute rule target previews", () => {
  it("formats previews as checkTitle • resourceName with safe fallbacks", () => {
    const preview = formatMuteRuleTargetPreview(makeFinding());
    const fallbackPreview = formatMuteRuleTargetPreview(
      makeFinding({
        checkId: "ec2_public_ip",
        checkTitle: "",
        resourceName: "",
        resourceUid: "arn:aws:ec2:::instance/i-123",
      }),
    );

    expect(preview).toBe("S3 Bucket Public Access • bucket-a");
    expect(fallbackPreview).toBe("ec2_public_ip • arn:aws:ec2:::instance/i-123");
  });

  it("hydrates all target labels for a rule and derives a compact summary", async () => {
    getLatestFindingsMock.mockResolvedValue({ data: [] });
    adaptFindingsByResourceResponseMock.mockReturnValue([
      makeFinding(),
      makeFinding({
        uid: "uid-2",
        checkId: "ec2_public_ip",
        checkTitle: "EC2 Public IP",
        resourceName: "instance-a",
        resourceUid: "arn:aws:ec2:::instance/i-123",
      }),
    ]);

    const result = await hydrateMuteRuleTargetPreviews([
      {
        type: "mute-rules",
        id: "mute-rule-1",
        attributes: {
          inserted_at: "2026-04-22T09:00:00Z",
          updated_at: "2026-04-22T09:05:00Z",
          name: "Rule 1",
          reason: "Reason 1",
          enabled: true,
          finding_uids: ["uid-1", "uid-2", "uid-3"],
        },
      },
    ]);

    expect(getLatestFindingsMock).toHaveBeenCalledWith({
      pageSize: 3,
      filters: {
        "filter[uid__in]": "uid-1,uid-2,uid-3",
      },
    });
    expect(adaptFindingsByResourceResponseMock).toHaveBeenCalledWith({
      data: [],
    });
    expect(result[0].targetLabels).toEqual([
      "S3 Bucket Public Access • bucket-a",
      "EC2 Public IP • instance-a",
      "uid-3",
    ]);
    expect(result[0].targetSummaryLabel).toBe(
      "S3 Bucket Public Access • bucket-a",
    );
    expect(result[0].hiddenTargetCount).toBe(2);
  });
});
