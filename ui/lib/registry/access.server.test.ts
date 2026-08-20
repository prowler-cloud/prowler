import { beforeEach, describe, expect, it, vi } from "vitest";

const { fetchCurrentUserMock } = vi.hoisted(() => ({
  fetchCurrentUserMock: vi.fn(),
}));
vi.mock("server-only", () => ({}));
vi.mock("@/lib/auth/current-user", () => ({
  fetchCurrentUser: fetchCurrentUserMock,
}));

import { REGISTRY_ACCESS } from "./access";
import { evaluateRegistryAccess } from "./access.server";

describe("evaluateRegistryAccess", () => {
  beforeEach(() => {
    vi.stubEnv("UI_CLOUD_ENABLED", "true");
    vi.stubEnv("UI_REGISTRY_ENABLED", "true");
    fetchCurrentUserMock.mockResolvedValue({ manageRegistry: true });
  });

  it("allows a fresh exact-true current permission with a five-second signal", async () => {
    // Given / When
    const result = await evaluateRegistryAccess("access-token");
    // Then
    expect(result.status).toBe(REGISTRY_ACCESS.ELIGIBLE);
  });

  it.each([
    [" true", "true", "access-token", true, REGISTRY_ACCESS.INELIGIBLE, 0],
    [undefined, "true", "access-token", true, REGISTRY_ACCESS.INELIGIBLE, 0],
    ["true", "false", "access-token", true, REGISTRY_ACCESS.INELIGIBLE, 0],
    ["true", "true", "access-token", false, REGISTRY_ACCESS.INELIGIBLE, 1],
    ["true", "true", "access-token", undefined, REGISTRY_ACCESS.UNKNOWN, 1],
    ["true", "true", "", true, REGISTRY_ACCESS.INELIGIBLE, 0],
  ])(
    "fails closed without trusting stale JWT authority",
    async (cloud, flag, token, permission, expected, calls) => {
      // Given
      vi.stubEnv("UI_CLOUD_ENABLED", cloud);
      vi.stubEnv("UI_REGISTRY_ENABLED", flag);
      fetchCurrentUserMock.mockResolvedValue({ manageRegistry: permission });
      // When / Then
      await expect(evaluateRegistryAccess(token)).resolves.toMatchObject({
        status: expected,
      });
      expect(fetchCurrentUserMock).toHaveBeenCalledTimes(calls);
    },
  );

  it("returns unknown for malformed, network, abort, and timeout evidence", async () => {
    // Given
    fetchCurrentUserMock
      .mockResolvedValueOnce({ manageRegistry: undefined })
      .mockRejectedValueOnce(new Error("network"))
      .mockRejectedValueOnce(new DOMException("aborted", "AbortError"))
      .mockImplementationOnce(
        (_token, { signal }) =>
          new Promise((_, reject) => signal.addEventListener("abort", reject)),
      );
    // When / Then
    const expectUnknown = () =>
      expect(evaluateRegistryAccess("access-token")).resolves.toMatchObject({
        status: REGISTRY_ACCESS.UNKNOWN,
      });
    await expectUnknown();
    await expectUnknown();
    await expectUnknown();
    vi.useFakeTimers();
    const result = evaluateRegistryAccess("access-token");
    await vi.advanceTimersByTimeAsync(5_000);
    await expect(result).resolves.toMatchObject({
      status: REGISTRY_ACCESS.UNKNOWN,
    });
    vi.useRealTimers();
  });
});
