import { beforeEach, describe, expect, it, vi } from "vitest";

const { fetchMock, isS3IntegrationLockedMock, revalidatePathMock } = vi.hoisted(
  () => ({
    fetchMock: vi.fn(),
    isS3IntegrationLockedMock: vi.fn(),
    revalidatePathMock: vi.fn(),
  }),
);

vi.mock("@/lib/s3-integration-access", async (importOriginal) => ({
  ...(await importOriginal<Record<string, unknown>>()),
  isS3IntegrationLocked: isS3IntegrationLockedMock,
}));

vi.mock("next/cache", () => ({
  revalidatePath: revalidatePathMock,
}));

vi.mock("@/lib", () => ({
  apiBaseUrl: "https://api.example.com/api/v1",
  getAuthHeaders: vi.fn().mockResolvedValue({ Authorization: "Bearer token" }),
  parseStringify: (value: unknown) => JSON.parse(JSON.stringify(value)),
}));

vi.mock("@/lib/server-actions-helper", () => ({
  handleApiError: () => ({ error: "An error occurred" }),
  handleApiResponse: vi.fn(),
}));

import { S3_INTEGRATION_LOCKED_ERROR } from "@/lib/s3-integration-access";

import {
  createIntegration,
  revalidateIntegrationConnectionPages,
  testIntegrationConnection,
} from "./integrations";

const buildIntegrationFormData = (integrationType: string) => {
  const formData = new FormData();
  formData.append("integration_type", integrationType);
  formData.append("configuration", JSON.stringify({}));
  formData.append("credentials", JSON.stringify({}));
  formData.append("providers", JSON.stringify([]));
  return formData;
};

describe("createIntegration", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.stubGlobal("fetch", fetchMock);
    fetchMock.mockResolvedValue(
      new Response(JSON.stringify({ data: { id: "integration-1" } }), {
        status: 201,
      }),
    );
  });

  it("refuses Amazon S3 for a tenant without a paid plan", async () => {
    // Given
    isS3IntegrationLockedMock.mockResolvedValue(true);

    // When
    const result = await createIntegration(
      buildIntegrationFormData("amazon_s3"),
    );

    // Then
    expect(result).toEqual({ error: S3_INTEGRATION_LOCKED_ERROR });
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("still creates other integrations for that tenant", async () => {
    // Given
    isS3IntegrationLockedMock.mockResolvedValue(true);

    // When
    const result = await createIntegration(buildIntegrationFormData("jira"));

    // Then
    expect(result).toMatchObject({ integrationId: "integration-1" });
    expect(fetchMock).toHaveBeenCalledOnce();
  });

  it("creates Amazon S3 when the tenant is not locked", async () => {
    // Given
    isS3IntegrationLockedMock.mockResolvedValue(false);

    // When
    const result = await createIntegration(
      buildIntegrationFormData("amazon_s3"),
    );

    // Then
    expect(result).toMatchObject({ integrationId: "integration-1" });
    expect(revalidatePathMock).toHaveBeenCalledWith("/integrations/amazon-s3");
  });
});

describe("testIntegrationConnection", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.stubGlobal("fetch", fetchMock);
    fetchMock.mockResolvedValue(
      new Response(JSON.stringify({ data: { id: "task-1", type: "tasks" } }), {
        status: 202,
      }),
    );
  });

  it("returns the task immediately for shared background tracking", async () => {
    // When
    const response = await testIntegrationConnection("jira-1");

    // Then
    expect(response).toEqual({
      success: true,
      message: "Connection test started. It may take some time to complete.",
      taskId: "task-1",
      data: { data: { id: "task-1", type: "tasks" } },
    });
  });

  it("revalidates every integration page through one shared action", async () => {
    // When
    await revalidateIntegrationConnectionPages();

    // Then
    expect(revalidatePathMock.mock.calls).toEqual([
      ["/integrations/amazon-s3"],
      ["/integrations/aws-security-hub"],
      ["/integrations/jira"],
      ["/integrations/slack"],
    ]);
  });
});
