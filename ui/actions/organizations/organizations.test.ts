import { beforeEach, describe, expect, it, vi } from "vitest";

import { ORG_SECRET_TYPE, ORGANIZATION_TYPE } from "@/types/organizations";

const {
  fetchMock,
  getAuthHeadersMock,
  handleApiErrorMock,
  handleApiResponseMock,
  revalidatePathMock,
} = vi.hoisted(() => ({
  fetchMock: vi.fn(),
  getAuthHeadersMock: vi.fn(),
  handleApiErrorMock: vi.fn(),
  handleApiResponseMock: vi.fn(),
  revalidatePathMock: vi.fn(),
}));

vi.mock("next/cache", () => ({
  revalidatePath: revalidatePathMock,
}));

vi.mock("@/lib", () => ({
  apiBaseUrl: "https://api.example.com/api/v1",
  getAuthHeaders: getAuthHeadersMock,
}));

vi.mock("@/lib/server-actions-helper", () => ({
  handleApiError: handleApiErrorMock,
  handleApiResponse: handleApiResponseMock,
}));

import {
  applyDiscovery,
  getDiscovery,
  listOrganizationNodesSafe,
  listOrganizationsSafe,
  triggerDiscovery,
  updateOrganizationSecret,
} from "./organizations";

describe("organizations actions", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.stubGlobal("fetch", fetchMock);
    getAuthHeadersMock.mockResolvedValue({ Authorization: "Bearer token" });
    handleApiErrorMock.mockReturnValue({ error: "Unexpected error" });
  });

  it("rejects invalid organization secret identifiers", async () => {
    // When
    const result = await updateOrganizationSecret("../secret-id", {
      secretType: ORG_SECRET_TYPE.ROLE,
      secret: {
        role_arn: "arn:aws:iam::123456789012:role/ProwlerOrgRole",
        external_id: "o-abc123def4",
      },
    });

    // Then
    expect(result).toEqual({ error: "Invalid organization secret ID" });
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("rejects invalid discovery identifiers before building the request URL", async () => {
    // When
    const result = await getDiscovery(
      "123e4567-e89b-12d3-a456-426614174000",
      "discovery/../id",
    );

    // Then
    expect(result).toEqual({ error: "Invalid discovery ID" });
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("rejects invalid organization identifiers before triggering discovery", async () => {
    // When
    const result = await triggerDiscovery("org/id-with-slash");

    // Then
    expect(result).toEqual({ error: "Invalid organization ID" });
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("revalidates providers only when apply discovery succeeds", async () => {
    // Given
    fetchMock.mockResolvedValue(
      new Response(JSON.stringify({ data: { id: "apply-1" } }), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      }),
    );
    handleApiResponseMock.mockResolvedValueOnce({ error: "Apply failed" });
    handleApiResponseMock.mockResolvedValueOnce({ data: { id: "apply-1" } });

    // When
    const failedResult = await applyDiscovery(
      "123e4567-e89b-12d3-a456-426614174000",
      "223e4567-e89b-12d3-a456-426614174111",
      { orgType: ORGANIZATION_TYPE.AWS, accounts: [], organizationalUnits: [] },
    );
    const successfulResult = await applyDiscovery(
      "123e4567-e89b-12d3-a456-426614174000",
      "223e4567-e89b-12d3-a456-426614174111",
      { orgType: ORGANIZATION_TYPE.AWS, accounts: [], organizationalUnits: [] },
    );

    // Then
    expect(failedResult).toEqual({ error: "Apply failed" });
    expect(successfulResult).toEqual({ data: { id: "apply-1" } });
    expect(revalidatePathMock).toHaveBeenCalledTimes(1);
    expect(revalidatePathMock).toHaveBeenCalledWith("/providers");
  });

  it("revalidates providers when response contains error set to null", async () => {
    // Given
    fetchMock.mockResolvedValue(
      new Response(JSON.stringify({ data: { id: "apply-2" } }), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      }),
    );
    handleApiResponseMock.mockResolvedValueOnce({
      data: { id: "apply-2" },
      error: null,
    });

    // When
    const result = await applyDiscovery(
      "123e4567-e89b-12d3-a456-426614174000",
      "223e4567-e89b-12d3-a456-426614174111",
      { orgType: ORGANIZATION_TYPE.AWS, accounts: [], organizationalUnits: [] },
    );

    // Then
    expect(result).toEqual({ data: { id: "apply-2" }, error: null });
    expect(revalidatePathMock).toHaveBeenCalledTimes(1);
    expect(revalidatePathMock).toHaveBeenCalledWith("/providers");
  });

  it("lists organizations across all types without a hardcoded org_type filter", async () => {
    // Given
    fetchMock.mockResolvedValue(
      new Response(JSON.stringify({ data: [] }), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      }),
    );
    handleApiResponseMock.mockResolvedValue({ data: [] });

    // When
    const result = await listOrganizationsSafe();

    // Then
    expect(result).toEqual({ data: [] });
    expect(fetchMock).toHaveBeenCalledTimes(1);
    expect(fetchMock.mock.calls[0]?.[0]).toBe(
      "https://api.example.com/api/v1/organizations?page%5Bsize%5D=100",
    );
  });

  it("lists organization nodes from the canonical endpoint", async () => {
    // Given
    fetchMock.mockResolvedValue(
      new Response(JSON.stringify({ data: [] }), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      }),
    );
    handleApiResponseMock.mockResolvedValue({ data: [] });

    // When
    const result = await listOrganizationNodesSafe();

    // Then
    expect(result).toEqual({ data: [] });
    expect(fetchMock).toHaveBeenCalledTimes(1);
    expect(fetchMock.mock.calls[0]?.[0]).toBe(
      "https://api.example.com/api/v1/organization-nodes?page%5Bsize%5D=100",
    );
  });

  it("flags an empty organizations payload as degraded when the safe request fails", async () => {
    // Given
    fetchMock.mockResolvedValue(
      new Response("Internal Server Error", {
        status: 500,
      }),
    );

    // When
    const result = await listOrganizationsSafe();

    // Then
    expect(result).toEqual({ data: [], error: true });
    expect(handleApiResponseMock).not.toHaveBeenCalled();
    expect(handleApiErrorMock).not.toHaveBeenCalled();
  });

  it("flags an empty organization nodes payload as degraded when the safe request fails", async () => {
    // Given
    fetchMock.mockResolvedValue(
      new Response("Internal Server Error", {
        status: 500,
      }),
    );

    // When
    const result = await listOrganizationNodesSafe();

    // Then
    expect(result).toEqual({ data: [], error: true });
    expect(handleApiResponseMock).not.toHaveBeenCalled();
    expect(handleApiErrorMock).not.toHaveBeenCalled();
  });
});
