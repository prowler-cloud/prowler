import { beforeEach, describe, expect, it, vi } from "vitest";

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

vi.mock("next/cache", () => ({ revalidatePath: vi.fn() }));
vi.mock("next/navigation", () => ({ redirect: vi.fn() }));

vi.mock("@/lib", () => ({
  apiBaseUrl: "https://api.example.com/api/v1",
  getAuthHeaders: getAuthHeadersMock,
}));

vi.mock("@/lib/server-actions-helper", () => ({
  handleApiError: handleApiErrorMock,
  handleApiResponse: handleApiResponseMock,
}));

import {
  isOnboardingProfileRecorded,
  skipOnboardingProfile,
  submitOnboardingProfile,
} from "./profile";

const ANSWERS = {
  declared_cloud_accounts: "11-50",
  declared_team_size: "2-5",
  declared_role: "security",
  declared_seniority: "director",
} as const;

describe("onboarding profile actions", () => {
  beforeEach(() => {
    vi.stubGlobal("fetch", fetchMock);
    fetchMock.mockReset();
    getAuthHeadersMock.mockReset().mockResolvedValue({});
    handleApiErrorMock.mockReset();
    handleApiResponseMock.mockReset().mockResolvedValue({ data: { id: "p1" } });
  });

  it("reports a stored profile and sends the declared buckets", async () => {
    // Given
    fetchMock.mockResolvedValue(new Response("{}", { status: 201 }));

    // When
    const result = await submitOnboardingProfile(ANSWERS);

    // Then
    expect(result).toEqual({ stored: true });
    const [url, init] = fetchMock.mock.calls[0];
    expect(url).toBe("https://api.example.com/api/v1/onboarding-profiles");
    expect(JSON.parse(init.body).data).toEqual({
      type: "onboarding-profiles",
      attributes: ANSWERS,
    });
  });

  it("records a skip as its own payload", async () => {
    // Given
    fetchMock.mockResolvedValue(new Response("{}", { status: 201 }));

    // When
    const result = await skipOnboardingProfile();

    // Then
    expect(result).toEqual({ stored: true });
    expect(JSON.parse(fetchMock.mock.calls[0][1].body).data.attributes).toEqual(
      {
        skipped: true,
      },
    );
  });

  it("treats a transport failure as not stored", async () => {
    // Given — the request never reaches the API.
    fetchMock.mockRejectedValue(new Error("network down"));

    // When
    const result = await submitOnboardingProfile(ANSWERS);

    // Then
    expect(result.stored).toBe(false);
    expect(result.error).toBeTruthy();
    expect(handleApiErrorMock).toHaveBeenCalledTimes(1);
  });

  it("treats a rejection without an errors array as not stored", async () => {
    // Given — e.g. a 403, which `handleApiResponse` returns as a bare error.
    fetchMock.mockResolvedValue(new Response("{}", { status: 403 }));
    handleApiResponseMock.mockResolvedValue({
      error: "Forbidden",
      status: 403,
    });

    // When
    const result = await submitOnboardingProfile(ANSWERS);

    // Then
    expect(result).toEqual({ stored: false, error: "Forbidden" });
  });

  it("surfaces the API's own message when the payload carries one", async () => {
    // Given
    fetchMock.mockResolvedValue(new Response("{}", { status: 400 }));
    handleApiResponseMock.mockResolvedValue({
      error: "Bad request",
      errors: [{ detail: "This field is required." }],
    });

    // When
    const result = await submitOnboardingProfile(ANSWERS);

    // Then
    expect(result).toEqual({
      stored: false,
      error: "This field is required.",
    });
  });

  it("treats a thrown server error as not stored", async () => {
    // Given — `handleApiResponse` throws on 5xx.
    fetchMock.mockResolvedValue(new Response("{}", { status: 500 }));
    handleApiResponseMock.mockRejectedValue(new Error("server error"));

    // When
    const result = await skipOnboardingProfile();

    // Then
    expect(result.stored).toBe(false);
    expect(handleApiErrorMock).toHaveBeenCalledTimes(1);
  });

  it.each([
    ["a submission", () => submitOnboardingProfile(ANSWERS)],
    ["a skip", () => skipOnboardingProfile()],
  ])(
    "reports %s as unstored when the session cannot be read",
    async (_, run) => {
      // Given — `auth()` rejects, e.g. a session this deployment cannot decode.
      getAuthHeadersMock.mockRejectedValue(new Error("session unreadable"));

      // When
      const result = await run();

      // Then — a result, never a throw: the step stays eligible next login.
      expect(result).toEqual({ stored: false, error: expect.any(String) });
      expect(fetchMock).not.toHaveBeenCalled();
      expect(handleApiErrorMock).toHaveBeenCalledTimes(1);
    },
  );

  it("reads an unreadable session as an unknown profile state", async () => {
    // Given — this runs in the root layout, so a throw would abort its render.
    getAuthHeadersMock.mockRejectedValue(new Error("session unreadable"));

    // When / Then — `undefined` makes the gate fail open.
    await expect(isOnboardingProfileRecorded()).resolves.toBeUndefined();
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("refuses answers outside the declared vocabulary", async () => {
    // When / Then — validation happens before any request.
    await expect(
      submitOnboardingProfile({
        ...ANSWERS,
        declared_role: "ceo",
      } as unknown as typeof ANSWERS),
    ).rejects.toThrow();
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it.each([
    ["an empty list", { data: [] }, false],
    ["a stored row", { data: [{ id: "p1" }] }, true],
  ])("reads %s as recorded=%s", async (_, payload, expected) => {
    // Given
    fetchMock.mockResolvedValue(
      new Response(JSON.stringify(payload), { status: 200 }),
    );

    // Then
    expect(await isOnboardingProfileRecorded()).toBe(expected);
  });

  it("returns undefined when the read fails, so the gate fails open", async () => {
    // Given
    fetchMock.mockResolvedValue(new Response("{}", { status: 500 }));

    // Then
    expect(await isOnboardingProfileRecorded()).toBeUndefined();
  });
});
