import { beforeEach, describe, expect, it, vi } from "vitest";

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
    // Given
    const formData = new FormData();
    formData.set("organizationSecretId", "../secret-id");
    formData.set("roleArn", "arn:aws:iam::123456789012:role/ProwlerOrgRole");
    formData.set("externalId", "o-abc123def4");

    // When
    const result = await updateOrganizationSecret(formData);

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
      [],
      [],
    );
    const successfulResult = await applyDiscovery(
      "123e4567-e89b-12d3-a456-426614174000",
      "223e4567-e89b-12d3-a456-426614174111",
      [],
      [],
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
      [],
      [],
    );

    // Then
    expect(result).toEqual({ data: { id: "apply-2" }, error: null });
    expect(revalidatePathMock).toHaveBeenCalledTimes(1);
    expect(revalidatePathMock).toHaveBeenCalledWith("/providers");
  });
});
