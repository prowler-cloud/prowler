import { beforeEach, describe, expect, it, vi } from "vitest";

const { fetchMock, getAuthHeadersMock, handleApiResponseMock } = vi.hoisted(
  () => ({
    fetchMock: vi.fn(),
    getAuthHeadersMock: vi.fn(),
    handleApiResponseMock: vi.fn(),
  }),
);

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
  handleApiError: vi.fn(),
  handleApiResponse: handleApiResponseMock,
}));

import { sendInvite } from "./invitation";

const inviteFormData = (source?: string) => {
  const formData = new FormData();
  formData.append("email", "teammate@company.com");
  formData.append("role", "22222222-2222-4222-8222-222222222222");
  if (source) formData.append("source", source);
  return formData;
};

describe("sendInvite", () => {
  beforeEach(() => {
    vi.stubGlobal("fetch", fetchMock);
    fetchMock.mockReset().mockResolvedValue(new Response("{}"));
    getAuthHeadersMock.mockReset().mockResolvedValue({});
    handleApiResponseMock
      .mockReset()
      .mockResolvedValue({ data: { id: "inv" } });
  });

  it("posts to the invitations endpoint without a source by default", async () => {
    // When
    await sendInvite(inviteFormData());

    // Then
    expect(fetchMock).toHaveBeenCalledWith(
      "https://api.example.com/api/v1/tenants/invitations",
      expect.objectContaining({ method: "POST" }),
    );
  });

  it("forwards the invitation source as a query param", async () => {
    // When
    await sendInvite(inviteFormData("onboarding"));

    // Then
    expect(fetchMock).toHaveBeenCalledWith(
      "https://api.example.com/api/v1/tenants/invitations?source=onboarding",
      expect.objectContaining({ method: "POST" }),
    );
    const body = JSON.parse(fetchMock.mock.calls[0]?.[1]?.body as string);
    expect(body.data.attributes).toEqual({ email: "teammate@company.com" });
  });
});
