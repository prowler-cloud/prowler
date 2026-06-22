import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const {
  fetchMock,
  getAuthHeadersMock,
  handleApiErrorMock,
  handleApiResponseMock,
} = vi.hoisted(() => ({
  fetchMock: vi.fn(),
  getAuthHeadersMock: vi.fn(),
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
}));

vi.mock("@/lib/server-actions-helper", () => ({
  handleApiError: handleApiErrorMock,
  handleApiResponse: handleApiResponseMock,
}));

import { addRole, updateRole } from "./roles";

const lastRequestBody = () => {
  const call = fetchMock.mock.calls.at(-1);
  if (!call) throw new Error("fetch was not called");
  const [, init] = call;
  return JSON.parse(String((init as RequestInit).body));
};

const makeRoleFormData = () => {
  const formData = new FormData();
  formData.set("name", "Alert manager");
  formData.set("manage_users", "false");
  formData.set("manage_account", "false");
  formData.set("manage_billing", "false");
  formData.set("manage_providers", "false");
  formData.set("manage_integrations", "false");
  formData.set("manage_scans", "false");
  formData.set("manage_alerts", "true");
  formData.set("unlimited_visibility", "false");
  return formData;
};

describe("role actions", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.stubGlobal("fetch", fetchMock);
    getAuthHeadersMock.mockResolvedValue({ Authorization: "Bearer token" });
    handleApiResponseMock.mockResolvedValue({ data: { id: "role-1" } });
    handleApiErrorMock.mockReturnValue({ error: "Unexpected error" });
    fetchMock.mockResolvedValue(
      new Response(JSON.stringify({ data: { id: "role-1" } }), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      }),
    );
  });

  afterEach(() => {
    vi.unstubAllEnvs();
  });

  it("includes manage_alerts when creating a role in Prowler Cloud", async () => {
    // Given
    vi.stubEnv("NEXT_PUBLIC_IS_CLOUD_ENV", "true");

    // When
    await addRole(makeRoleFormData());

    // Then
    expect(lastRequestBody().data.attributes.manage_alerts).toBe(true);
  });

  it("omits manage_alerts when creating a role outside Prowler Cloud", async () => {
    // Given
    vi.stubEnv("NEXT_PUBLIC_IS_CLOUD_ENV", "false");

    // When
    await addRole(makeRoleFormData());

    // Then
    expect(lastRequestBody().data.attributes).not.toHaveProperty(
      "manage_alerts",
    );
  });

  it("includes manage_alerts when updating a role in Prowler Cloud", async () => {
    // Given
    vi.stubEnv("NEXT_PUBLIC_IS_CLOUD_ENV", "true");

    // When
    await updateRole(makeRoleFormData(), "role-1");

    // Then
    expect(lastRequestBody().data.attributes.manage_alerts).toBe(true);
  });
});
