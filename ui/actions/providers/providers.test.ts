import { beforeEach, describe, expect, it, vi } from "vitest";

const {
  fetchMock,
  getAuthHeadersMock,
  getFormValueMock,
  handleApiErrorMock,
  handleApiResponseMock,
} = vi.hoisted(() => ({
  fetchMock: vi.fn(),
  getAuthHeadersMock: vi.fn(),
  getFormValueMock: vi.fn(),
  handleApiErrorMock: vi.fn(),
  handleApiResponseMock: vi.fn(),
}));

vi.mock("next/cache", () => ({
  revalidatePath: vi.fn(),
}));

vi.mock("next/navigation", () => ({
  redirect: vi.fn(),
}));

vi.mock("@/lib", () => ({
  apiBaseUrl: "https://api.example.com/api/v1",
  getAuthHeaders: getAuthHeadersMock,
  getFormValue: getFormValueMock,
  wait: vi.fn(),
}));

vi.mock("@/lib/provider-credentials/build-crendentials", () => ({
  buildSecretConfig: vi.fn(() => ({
    secretType: "access-secret-key",
    secret: { key: "value" },
  })),
}));

vi.mock("@/lib/provider-filters", () => ({
  appendSanitizedProviderInFilters: vi.fn(),
}));

vi.mock("@/lib/server-actions-helper", () => ({
  handleApiError: handleApiErrorMock,
  handleApiResponse: handleApiResponseMock,
}));

import {
  addCredentialsProvider,
  addProvider,
  checkConnectionProvider,
  updateCredentialsProvider,
} from "./providers";

describe("providers actions", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.stubGlobal("fetch", fetchMock);
    getAuthHeadersMock.mockResolvedValue({ Authorization: "Bearer token" });
    getFormValueMock.mockImplementation((formData: FormData, field: string) =>
      formData.get(field),
    );
    handleApiErrorMock.mockReturnValue({ error: "Unexpected error" });
    handleApiResponseMock.mockResolvedValue({ data: { id: "secret-1" } });
    fetchMock.mockResolvedValue(
      new Response(JSON.stringify({ data: { id: "secret-1" } }), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      }),
    );
  });

  it("should revalidate providers after linking a cloud provider", async () => {
    // Given
    const formData = new FormData();
    formData.set("providerType", "aws");
    formData.set("providerUid", "111111111111");

    // When
    await addProvider(formData);

    // Then
    expect(handleApiResponseMock).toHaveBeenCalledWith(
      expect.any(Response),
      "/providers",
    );
  });

  it("should revalidate providers after adding credentials in the wizard", async () => {
    // Given
    const formData = new FormData();
    formData.set("providerId", "provider-1");
    formData.set("providerType", "aws");

    // When
    await addCredentialsProvider(formData);

    // Then
    expect(handleApiResponseMock).toHaveBeenCalledWith(
      expect.any(Response),
      "/providers",
    );
  });

  it("should revalidate providers after updating credentials in the wizard", async () => {
    // Given
    const formData = new FormData();
    formData.set("providerId", "provider-1");
    formData.set("providerType", "oraclecloud");

    // When
    await updateCredentialsProvider("secret-1", formData);

    // Then
    expect(handleApiResponseMock).toHaveBeenCalledWith(
      expect.any(Response),
      "/providers",
    );
  });

  it("should revalidate providers when checking connection from the wizard", async () => {
    // Given
    const formData = new FormData();
    formData.set("providerId", "provider-1");

    // When
    await checkConnectionProvider(formData);

    // Then
    expect(handleApiResponseMock).toHaveBeenCalledWith(
      expect.any(Response),
      "/providers",
    );
  });
});
