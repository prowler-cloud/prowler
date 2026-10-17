import { beforeEach, describe, expect, it, vi } from "vitest";

const { fetchMock, getAuthHeadersMock, revalidatePathMock } = vi.hoisted(
  () => ({
    fetchMock: vi.fn(),
    getAuthHeadersMock: vi.fn(),
    revalidatePathMock: vi.fn(),
  }),
);

vi.mock("@/lib/helper", () => ({
  apiBaseUrl: "https://api.test/api/v1",
  getAuthHeaders: getAuthHeadersMock,
}));

vi.mock("next/cache", () => ({
  revalidatePath: revalidatePathMock,
}));

import { createMuteRule } from "./mute-rules";

const NAME_CONFLICT_DETAIL = "A mute rule with this name already exists.";

const errorResponse = (contentType: string, body: string, status = 400) =>
  new Response(body, {
    status,
    headers: { "Content-Type": contentType },
  });

const nameConflictBody = JSON.stringify({
  errors: [
    {
      detail: NAME_CONFLICT_DETAIL,
      status: "400",
      source: { pointer: "/data/attributes/name" },
      code: "invalid",
    },
  ],
});

const muteRuleFormData = () => {
  const formData = new FormData();
  formData.set("name", "Root account has a hardware MFA device enabled");
  formData.set("reason", "Not our approach here with SSO");
  formData.set("finding_ids", JSON.stringify(["finding-1"]));
  return formData;
};

beforeEach(() => {
  vi.clearAllMocks();
  vi.stubGlobal("fetch", fetchMock);
  vi.spyOn(console, "error").mockImplementation(() => {});
  getAuthHeadersMock.mockResolvedValue({ Authorization: "Bearer token" });
});

describe("createMuteRule", () => {
  it("should return only the error detail for a JSON:API error response", async () => {
    fetchMock.mockResolvedValue(
      errorResponse("application/vnd.api+json", nameConflictBody),
    );

    const result = await createMuteRule(null, muteRuleFormData());

    expect(result?.errors?.general).toBe(NAME_CONFLICT_DETAIL);
    expect(revalidatePathMock).not.toHaveBeenCalled();
  });

  it("should return only the error detail for a plain JSON error response", async () => {
    fetchMock.mockResolvedValue(
      errorResponse("application/json", nameConflictBody),
    );

    const result = await createMuteRule(null, muteRuleFormData());

    expect(result?.errors?.general).toBe(NAME_CONFLICT_DETAIL);
  });

  it("should return the response text for a non-JSON error response", async () => {
    fetchMock.mockResolvedValue(
      errorResponse("text/plain", "Bad gateway", 502),
    );

    const result = await createMuteRule(null, muteRuleFormData());

    expect(result?.errors?.general).toBe("Bad gateway");
  });
});
