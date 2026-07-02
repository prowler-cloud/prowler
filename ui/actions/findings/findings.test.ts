import { beforeEach, describe, expect, it, vi } from "vitest";

const {
  fetchMock,
  getAuthHeadersMock,
  handleApiResponseMock,
  appendSanitizedProviderTypeFiltersMock,
  redirectMock,
} = vi.hoisted(() => ({
  fetchMock: vi.fn(),
  getAuthHeadersMock: vi.fn(),
  handleApiResponseMock: vi.fn(),
  appendSanitizedProviderTypeFiltersMock: vi.fn(),
  redirectMock: vi.fn(),
}));

vi.mock("next/navigation", () => ({
  redirect: redirectMock,
}));

vi.mock("@/lib", () => ({
  apiBaseUrl: "https://api.example.com/api/v1",
  getAuthHeaders: getAuthHeadersMock,
}));

vi.mock("@/lib/provider-filters", () => ({
  appendSanitizedProviderTypeFilters: appendSanitizedProviderTypeFiltersMock,
}));

vi.mock("@/lib/server-actions-helper", () => ({
  handleApiResponse: handleApiResponseMock,
}));

import { FINDING_TRIAGE_STATUS } from "@/types/findings-triage";

import { getFindings, getLatestFindings } from "./findings";

const findingsResponse = {
  data: [
    {
      type: "findings",
      id: "finding-1",
      attributes: {
        uid: "prowler-finding-uid-1",
        status: "FAIL",
        triage_status: "under_review",
        triage_has_note: true,
      },
    },
  ],
  meta: { pagination: { page: 1 } },
};

describe("findings actions triage projection", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.stubGlobal("fetch", fetchMock);
    vi.stubEnv("NEXT_PUBLIC_IS_CLOUD_ENV", "false");
    getAuthHeadersMock.mockResolvedValue({ Authorization: "Bearer token" });
    fetchMock.mockResolvedValue(new Response("", { status: 200 }));
    handleApiResponseMock.mockResolvedValue(findingsResponse);
  });

  it("should attach domain triage DTOs to historical findings responses", async () => {
    // When
    const result = await getFindings({ page: 1, pageSize: 10 });

    // Then
    expect(result?.data[0].triage).toEqual(
      expect.objectContaining({
        findingId: "finding-1",
        findingUid: "prowler-finding-uid-1",
        status: FINDING_TRIAGE_STATUS.UNDER_REVIEW,
        label: "Under Review",
        hasVisibleNote: true,
        canEdit: false,
        disabledReason: "cloud_only",
      }),
    );
    expect(result?.data[0].triage).not.toHaveProperty("triage_status");
    expect(result?.data[0].triage).not.toHaveProperty("attributes");
  });

  it("should attach domain triage DTOs to latest findings responses", async () => {
    // Given
    vi.stubEnv("NEXT_PUBLIC_IS_CLOUD_ENV", "true");

    // When
    const result = await getLatestFindings({ page: 1, pageSize: 10 });

    // Then
    expect(result?.data[0].triage).toEqual(
      expect.objectContaining({
        status: FINDING_TRIAGE_STATUS.UNDER_REVIEW,
        canEdit: true,
      }),
    );
    expect(result?.data[0].triage).not.toHaveProperty("disabledReason");
  });
});
