import { beforeEach, describe, expect, it, vi } from "vitest";

const {
  fetchMock,
  getAuthHeadersMock,
  getFormValueMock,
  handleApiErrorMock,
  handleApiResponseMock,
  waitMock,
} = vi.hoisted(() => ({
  fetchMock: vi.fn(),
  getAuthHeadersMock: vi.fn(),
  getFormValueMock: vi.fn(),
  handleApiErrorMock: vi.fn(),
  handleApiResponseMock: vi.fn(),
  waitMock: vi.fn(),
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
  wait: waitMock,
}));

vi.mock("@/lib/provider-credentials/build-credentials", () => ({
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
  startProviderConnectionChecks,
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

describe("startProviderConnectionChecks", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.stubGlobal("fetch", fetchMock);
    getAuthHeadersMock.mockResolvedValue({ Authorization: "Bearer token" });
    handleApiErrorMock.mockReturnValue({ error: "Unexpected error" });
    fetchMock.mockResolvedValue(new Response(null, { status: 202 }));
  });

  it("dispatches one check per provider and returns the task each is tested by", async () => {
    // Given
    handleApiResponseMock.mockImplementation(async () => ({
      data: { id: `task-${handleApiResponseMock.mock.calls.length}` },
    }));

    // When
    const outcomes = await startProviderConnectionChecks([
      "provider-1",
      "provider-2",
    ]);

    // Then
    expect(fetchMock).toHaveBeenCalledTimes(2);
    expect(Object.keys(outcomes).sort()).toEqual(["provider-1", "provider-2"]);
    expect(Object.values(outcomes).map((outcome) => outcome.taskId)).toEqual(
      expect.arrayContaining(["task-1", "task-2"]),
    );
  });

  it("skips the single-provider padding and the per-provider revalidation", async () => {
    // Given
    handleApiResponseMock.mockResolvedValue({ data: { id: "task-1" } });

    // When
    await startProviderConnectionChecks(["provider-1", "provider-2"]);

    // Then
    expect(waitMock).not.toHaveBeenCalled();
    expect(handleApiResponseMock).toHaveBeenCalledWith(
      expect.any(Response),
      undefined,
    );
  });

  it("keeps a failed dispatch to its own provider, error payload included", async () => {
    // Given
    const failure = { error: "Provider not found.", status: 404 };
    handleApiResponseMock
      .mockResolvedValueOnce({ data: { id: "task-1" } })
      .mockResolvedValueOnce(failure);

    // When
    const outcomes = await startProviderConnectionChecks([
      "provider-1",
      "provider-2",
    ]);

    // Then
    expect(outcomes["provider-1"]).toEqual({ taskId: "task-1" });
    expect(outcomes["provider-2"]).toEqual({ error: failure });
  });

  it("keeps a thrown request to its own provider", async () => {
    // Given
    handleApiResponseMock.mockResolvedValue({ data: { id: "task-1" } });
    fetchMock
      .mockResolvedValueOnce(new Response(null, { status: 202 }))
      .mockRejectedValueOnce(new Error("socket hang up"));

    // When
    const outcomes = await startProviderConnectionChecks([
      "provider-1",
      "provider-2",
    ]);

    // Then
    expect(outcomes["provider-1"]).toEqual({ taskId: "task-1" });
    expect(outcomes["provider-2"]).toEqual({
      error: { error: "Unexpected error" },
    });
  });

  it("ignores blank and duplicated ids", async () => {
    // Given
    handleApiResponseMock.mockResolvedValue({ data: { id: "task-1" } });

    // When
    const outcomes = await startProviderConnectionChecks([
      "provider-1",
      "provider-1",
      "",
    ]);

    // Then
    expect(fetchMock).toHaveBeenCalledTimes(1);
    expect(Object.keys(outcomes)).toEqual(["provider-1"]);
  });
});
