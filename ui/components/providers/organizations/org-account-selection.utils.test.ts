import { describe, expect, it, vi } from "vitest";

import { CONNECTION_TEST_STATUS } from "@/types/organizations";

import {
  buildAccountToProviderMap,
  canAdvanceToLaunchStep,
  getLaunchableProviderIds,
  pollConnectionTask,
  runWithConcurrencyLimit,
} from "./org-account-selection.utils";

describe("buildAccountToProviderMap", () => {
  it("uses explicit account-provider mappings when apply response is unordered", async () => {
    // Given
    const resolveProviderUidById = vi.fn();
    const selectedAccountIds = ["111111111111", "222222222222"];
    const providerIds = ["provider-b", "provider-a"];
    const applyResult = {
      data: {
        attributes: {
          account_provider_mappings: [
            {
              account_id: "111111111111",
              provider_id: "provider-a",
            },
            {
              account_id: "222222222222",
              provider_id: "provider-b",
            },
          ],
        },
      },
    };

    // When
    const map = await buildAccountToProviderMap({
      selectedAccountIds,
      providerIds,
      applyResult,
      resolveProviderUidById,
    });

    // Then
    expect(map.get("111111111111")).toBe("provider-a");
    expect(map.get("222222222222")).toBe("provider-b");
    expect(resolveProviderUidById).not.toHaveBeenCalled();
  });

  it("falls back to provider uid matching when explicit mappings are missing", async () => {
    // Given
    const selectedAccountIds = ["111111111111", "222222222222"];
    const providerIds = ["provider-a", "provider-b", "provider-c"];
    const resolveProviderUidById = vi.fn(async (providerId: string) => {
      if (providerId === "provider-a") return "222222222222";
      if (providerId === "provider-c") return "111111111111";
      return "999999999999";
    });

    // When
    const map = await buildAccountToProviderMap({
      selectedAccountIds,
      providerIds,
      applyResult: {},
      resolveProviderUidById,
    });

    // Then
    expect(map.get("111111111111")).toBe("provider-c");
    expect(map.get("222222222222")).toBe("provider-a");
  });
});

describe("runWithConcurrencyLimit", () => {
  it("processes work with the configured concurrency cap", async () => {
    // Given
    const items = Array.from({ length: 8 }, (_, index) => index + 1);
    let activeWorkers = 0;
    let maxActiveWorkers = 0;

    // When
    const results = await runWithConcurrencyLimit(items, 3, async (item) => {
      activeWorkers += 1;
      maxActiveWorkers = Math.max(maxActiveWorkers, activeWorkers);
      await new Promise((resolve) => setTimeout(resolve, 1));
      activeWorkers -= 1;
      return item * 2;
    });

    // Then
    expect(maxActiveWorkers).toBeLessThanOrEqual(3);
    expect(results).toEqual([2, 4, 6, 8, 10, 12, 14, 16]);
  });
});

describe("pollConnectionTask", () => {
  it("uses progressive delays and returns connection result from the final task payload", async () => {
    // Given
    const sleeps: number[] = [];
    const getTaskById = vi
      .fn()
      .mockResolvedValueOnce({
        data: { attributes: { state: "executing" } },
      })
      .mockResolvedValueOnce({
        data: { attributes: { state: "executing" } },
      })
      .mockResolvedValueOnce({
        data: {
          attributes: {
            state: "completed",
            result: { connected: false, error: "Role trust policy mismatch." },
          },
        },
      });

    // When
    const result = await pollConnectionTask("task-1", {
      getTaskById,
      sleep: async (delay) => {
        sleeps.push(delay);
      },
      maxRetries: 5,
    });

    // Then
    expect(sleeps).toEqual([2000, 3000]);
    expect(getTaskById).toHaveBeenCalledTimes(3);
    expect(result).toEqual({
      success: false,
      error: "Role trust policy mismatch.",
    });
  });

  it("stops polling when aborted", async () => {
    // Given
    const abortController = new AbortController();
    const getTaskById = vi
      .fn()
      .mockResolvedValue({ data: { attributes: { state: "executing" } } });
    const sleep = vi.fn(async () => {
      abortController.abort();
    });

    // When
    const result = await pollConnectionTask("task-1", {
      getTaskById,
      sleep,
      signal: abortController.signal,
      maxRetries: 5,
    });

    // Then
    expect(getTaskById).toHaveBeenCalledTimes(1);
    expect(result).toEqual({
      success: false,
      error: "Connection test cancelled.",
    });
  });
});

describe("launch gating", () => {
  it("blocks advancing when all tested providers failed", () => {
    // Given
    const providerIds = ["provider-a", "provider-b"];
    const connectionResults = {
      "provider-a": CONNECTION_TEST_STATUS.ERROR,
      "provider-b": CONNECTION_TEST_STATUS.ERROR,
    };

    // When
    const launchableProviderIds = getLaunchableProviderIds(
      providerIds,
      connectionResults,
    );
    const canAdvance = canAdvanceToLaunchStep(providerIds, connectionResults);

    // Then
    expect(launchableProviderIds).toEqual([]);
    expect(canAdvance).toBe(false);
  });

  it("allows advancing and keeps only successful providers", () => {
    // Given
    const providerIds = ["provider-a", "provider-b"];
    const connectionResults = {
      "provider-a": CONNECTION_TEST_STATUS.SUCCESS,
      "provider-b": CONNECTION_TEST_STATUS.ERROR,
    };

    // When
    const launchableProviderIds = getLaunchableProviderIds(
      providerIds,
      connectionResults,
    );
    const canAdvance = canAdvanceToLaunchStep(providerIds, connectionResults);

    // Then
    expect(launchableProviderIds).toEqual(["provider-a"]);
    expect(canAdvance).toBe(true);
  });
});
