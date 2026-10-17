import { beforeEach, describe, expect, it, vi } from "vitest";

const { fetchCurrentUserMock } = vi.hoisted(() => ({
  fetchCurrentUserMock: vi.fn(),
}));
vi.mock("server-only", () => ({}));
vi.mock("@/lib/auth/current-user", () => ({
  fetchCurrentUser: fetchCurrentUserMock,
}));

import { REGISTRY_ACCESS } from "./access";
import {
  evaluateRegistryAccess,
  evaluateRegistryProviderAccess,
} from "./access.server";

describe("Registry provider onboarding access", () => {
  beforeEach(() => {
    vi.stubEnv("UI_CLOUD_ENABLED", "true");
    vi.stubEnv("UI_REGISTRY_ENABLED", "true");
  });

  it.each([false, undefined])(
    "allows provider managers without Registry permission (%s)",
    async (manageRegistry) => {
      // Given
      fetchCurrentUserMock.mockResolvedValue({
        manageRegistry,
        permissions: { manage_providers: true },
      });
      // When / Then
      await expect(
        evaluateRegistryProviderAccess("access-token"),
      ).resolves.toEqual({
        status: REGISTRY_ACCESS.ELIGIBLE,
      });
      await expect(evaluateRegistryAccess("access-token")).resolves.not.toEqual(
        {
          status: REGISTRY_ACCESS.ELIGIBLE,
        },
      );
    },
  );

  it("denies onboarding to a Registry manager without manage_providers", async () => {
    // Given
    fetchCurrentUserMock.mockResolvedValue({
      manageRegistry: true,
      permissions: { manage_providers: false },
    });
    // When / Then
    await expect(
      evaluateRegistryProviderAccess("access-token"),
    ).resolves.toEqual({
      status: REGISTRY_ACCESS.INELIGIBLE,
    });
    await expect(evaluateRegistryAccess("access-token")).resolves.toEqual({
      status: REGISTRY_ACCESS.ELIGIBLE,
    });
  });

  it.each([
    ["false", "true", "access-token"],
    ["true", "false", "access-token"],
    ["true", "true", ""],
  ])(
    "requires enabled flags and a token: %j / %j / %j",
    async (cloud, flag, token) => {
      // Given
      vi.stubEnv("UI_CLOUD_ENABLED", cloud);
      vi.stubEnv("UI_REGISTRY_ENABLED", flag);
      // When / Then
      await expect(evaluateRegistryProviderAccess(token)).resolves.toEqual({
        status: REGISTRY_ACCESS.INELIGIBLE,
      });
      expect(fetchCurrentUserMock).not.toHaveBeenCalled();
    },
  );

  it("checks current provider permission again after revocation", async () => {
    // Given
    fetchCurrentUserMock
      .mockResolvedValueOnce({ permissions: { manage_providers: true } })
      .mockResolvedValueOnce({ permissions: { manage_providers: false } });
    // When / Then
    await expect(
      evaluateRegistryProviderAccess("access-token"),
    ).resolves.toEqual({
      status: REGISTRY_ACCESS.ELIGIBLE,
    });
    await expect(
      evaluateRegistryProviderAccess("access-token"),
    ).resolves.toEqual({
      status: REGISTRY_ACCESS.INELIGIBLE,
    });
  });
});

describe("evaluateRegistryAccess", () => {
  beforeEach(() => {
    vi.stubEnv("UI_CLOUD_ENABLED", "true");
    vi.stubEnv("UI_REGISTRY_ENABLED", "true");
    fetchCurrentUserMock.mockResolvedValue({ manageRegistry: true });
  });

  it("allows a fresh exact-true current permission without lease metadata", async () => {
    // Given / When
    const result = await evaluateRegistryAccess("access-token");
    // Then
    expect(result).toStrictEqual({ status: REGISTRY_ACCESS.ELIGIBLE });
  });

  it.each([
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

  it.each([
    [" true ", "true"],
    ["true", " true "],
    ["\ttrue\n", "\ttrue\n"],
  ])(
    "accepts whitespace around enabled flags: %j / %j",
    async (cloud, flag) => {
      // Given
      vi.stubEnv("UI_CLOUD_ENABLED", cloud);
      vi.stubEnv("UI_REGISTRY_ENABLED", flag);
      // When / Then
      await expect(evaluateRegistryAccess("access-token")).resolves.toEqual({
        status: REGISTRY_ACCESS.ELIGIBLE,
      });
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
