import { describe, expect, it, vi } from "vitest";

import { CONNECTION_TEST_STATUS } from "@/types/organizations";
import { CONNECTION_CHECK_STATUS } from "@/types/providers";

import {
  buildCandidateToProviderMap,
  canAdvanceToLaunchStep,
  CONNECTION_CHECK_DEFAULT_DELAYS_MS,
  CONNECTION_CHECK_MAX_RETRIES,
  getLaunchableProviderIds,
  pollConnectionTasks,
} from "./org-account-selection.utils";

describe("buildCandidateToProviderMap", () => {
  it("matches providers to candidates by uid, not by position", async () => {
    // Given — relationship order is not selection order, so pairing them by index
    // would mismatch every candidate.
    const selectedCandidateIds = ["111111111111", "222222222222"];
    const providerIds = ["provider-b", "provider-a"];
    const resolveProviderUids = vi.fn(async () => ({
      "provider-a": "111111111111",
      "provider-b": "222222222222",
    }));

    // When
    const map = await buildCandidateToProviderMap({
      selectedCandidateIds,
      providerIds,
      resolveProviderUids,
    });

    // Then — resolved in one call, for all providers at once.
    expect(map.get("111111111111")).toBe("provider-a");
    expect(map.get("222222222222")).toBe("provider-b");
    expect(resolveProviderUids).toHaveBeenCalledTimes(1);
    expect(resolveProviderUids).toHaveBeenCalledWith(providerIds);
  });

  it("leaves out providers whose uid did not resolve or is outside the selection", async () => {
    // Given — one provider resolves to a candidate nobody selected, one not at all.
    const selectedCandidateIds = ["111111111111", "222222222222"];
    const providerIds = ["provider-a", "provider-b", "provider-c"];
    const resolveProviderUids = vi.fn(async () => ({
      "provider-a": "222222222222",
      "provider-b": "999999999999",
    }));

    // When
    const map = await buildCandidateToProviderMap({
      selectedCandidateIds,
      providerIds,
      resolveProviderUids,
    });

    // Then
    expect(map.get("222222222222")).toBe("provider-a");
    expect(map.size).toBe(1);
  });
});

const executing = { data: { attributes: { state: "executing" } } };
const completed = (connected: boolean, error?: string) => ({
  data: { attributes: { state: "completed", result: { connected, error } } },
});

describe("pollConnectionTasks", () => {
  it("reports each task the round it settles instead of waiting for the slowest", async () => {
    // Given — one account connects on the first round, the other three rounds later.
    const rounds: string[][] = [];
    const getTasksByIds = vi.fn(async (taskIds: string[]) => {
      rounds.push([...taskIds]);
      const round = rounds.length;
      return {
        "task-fast": round >= 1 ? completed(true) : executing,
        "task-slow":
          round >= 3
            ? completed(false, "Role trust policy mismatch.")
            : executing,
      };
    });
    const settled: Array<[string, unknown]> = [];

    // When
    await pollConnectionTasks(["task-fast", "task-slow"], {
      onSettled: (taskId, result) => settled.push([taskId, result]),
      getTasksByIds,
      sleep: async () => {},
      maxRetries: 5,
    });

    // Then — the fast one is reported after round 1 and dropped from later reads,
    // while the slow one is still pending.
    expect(settled).toEqual([
      ["task-fast", { status: CONNECTION_CHECK_STATUS.SUCCESS }],
      [
        "task-slow",
        {
          status: CONNECTION_CHECK_STATUS.FAILED,
          error: "Role trust policy mismatch.",
        },
      ],
    ]);
    expect(rounds).toEqual([
      ["task-fast", "task-slow"],
      ["task-slow"],
      ["task-slow"],
    ]);
  });

  it("reads every pending task in one call per round, with progressive delays", async () => {
    // Given — a client-side loop would cost one round trip per task per round.
    const sleeps: number[] = [];
    const getTasksByIds = vi
      .fn()
      .mockResolvedValueOnce({ "task-a": executing, "task-b": executing })
      .mockResolvedValueOnce({ "task-a": executing, "task-b": executing })
      .mockResolvedValueOnce({
        "task-a": completed(true),
        "task-b": completed(true),
      });

    // When
    await pollConnectionTasks(["task-a", "task-b"], {
      onSettled: () => {},
      getTasksByIds,
      sleep: async (delay) => {
        sleeps.push(delay);
      },
      maxRetries: 5,
    });

    // Then
    expect(getTasksByIds).toHaveBeenCalledTimes(3);
    expect(sleeps).toEqual([2000, 3000]);
  });

  it("stops polling when aborted and cancels whatever had not settled", async () => {
    // Given
    const abortController = new AbortController();
    const getTasksByIds = vi.fn(async () => ({
      "task-a": completed(true),
      "task-b": executing,
    }));
    const sleep = vi.fn(async () => {
      abortController.abort();
    });
    const settled: Array<[string, unknown]> = [];

    // When
    await pollConnectionTasks(["task-a", "task-b"], {
      onSettled: (taskId, result) => settled.push([taskId, result]),
      getTasksByIds,
      sleep,
      signal: abortController.signal,
      maxRetries: 5,
    });

    // Then — the settled result stands; the pending one is reported cancelled.
    expect(getTasksByIds).toHaveBeenCalledTimes(1);
    expect(settled).toEqual([
      ["task-a", { status: CONNECTION_CHECK_STATUS.SUCCESS }],
      [
        "task-b",
        {
          status: CONNECTION_CHECK_STATUS.FAILED,
          error: "Connection test cancelled.",
        },
      ],
    ]);
  });

  it("reports cancellation instead of accepting the resolver's result when abort lands mid-await", async () => {
    // Given: the wait exhausts with one task still pending, and the caller's
    // `resolveExhausted` aborts the flow while its own lookup is in flight
    // (e.g. the wizard unmounted). The abort must win even though the
    // resolver still returns a result.
    const abortController = new AbortController();
    const getTasksByIds = vi.fn(async () => ({
      "task-a": executing,
    }));
    const settled: Array<[string, unknown]> = [];
    const resolveExhausted = vi.fn(async () => {
      abortController.abort();
      return { status: CONNECTION_CHECK_STATUS.SUCCESS };
    });

    // When
    await pollConnectionTasks(["task-a"], {
      onSettled: (taskId, result) => settled.push([taskId, result]),
      getTasksByIds,
      sleep: async () => {},
      maxRetries: 1,
      signal: abortController.signal,
      resolveExhausted,
    });

    // Then: cancelled, not the resolver's (stale) success.
    expect(resolveExhausted).toHaveBeenCalledWith("task-a");
    expect(settled).toEqual([
      [
        "task-a",
        {
          status: CONNECTION_CHECK_STATUS.FAILED,
          error: "Connection test cancelled.",
        },
      ],
    ]);
  });

  it("stops resolving further tasks once abort lands between resolveExhausted calls", async () => {
    // Given: two tasks are still pending at exhaustion; abort fires while the
    // first is being resolved, so the second must never be looked up.
    const abortController = new AbortController();
    const getTasksByIds = vi.fn(async () => ({
      "task-a": executing,
      "task-b": executing,
    }));
    const settled: Array<[string, unknown]> = [];
    const resolveExhausted = vi.fn(async (taskId: string) => {
      if (taskId === "task-a") {
        abortController.abort();
      }
      return { status: CONNECTION_CHECK_STATUS.SUCCESS };
    });

    // When
    await pollConnectionTasks(["task-a", "task-b"], {
      onSettled: (taskId, result) => settled.push([taskId, result]),
      getTasksByIds,
      sleep: async () => {},
      maxRetries: 1,
      signal: abortController.signal,
      resolveExhausted,
    });

    // Then
    expect(resolveExhausted).toHaveBeenCalledTimes(1);
    expect(resolveExhausted).toHaveBeenCalledWith("task-a");
    expect(settled).toEqual([
      [
        "task-a",
        {
          status: CONNECTION_CHECK_STATUS.FAILED,
          error: "Connection test cancelled.",
        },
      ],
      [
        "task-b",
        {
          status: CONNECTION_CHECK_STATUS.FAILED,
          error: "Connection test cancelled.",
        },
      ],
    ]);
  });

  it("times out only the tasks that never settled", async () => {
    // Given
    const getTasksByIds = vi.fn(async () => ({
      "task-a": completed(true),
      "task-b": executing,
    }));
    const settled: Array<[string, unknown]> = [];

    // When
    await pollConnectionTasks(["task-a", "task-b"], {
      onSettled: (taskId, result) => settled.push([taskId, result]),
      getTasksByIds,
      sleep: async () => {},
      maxRetries: 2,
    });

    // Then
    expect(settled).toEqual([
      ["task-a", { status: CONNECTION_CHECK_STATUS.SUCCESS }],
      [
        "task-b",
        {
          status: CONNECTION_CHECK_STATUS.FAILED,
          error: "Connection test timed out.",
        },
      ],
    ]);
  });

  it("sizes the default wait past the backend's 120s provider-connection-check time limit", () => {
    // The last delay in the ladder repeats for every retry beyond it, so the
    // worst-case total wait is (maxRetries - 1) * lastDelay.
    const lastDelay =
      CONNECTION_CHECK_DEFAULT_DELAYS_MS[
        CONNECTION_CHECK_DEFAULT_DELAYS_MS.length - 1
      ];
    const worstCaseWaitMs = (CONNECTION_CHECK_MAX_RETRIES - 1) * lastDelay;

    expect(worstCaseWaitMs).toBeGreaterThan(120_000);
  });

  it("resolves a still-pending task from the caller once the wait is exhausted", async () => {
    // Given: the batch read never settles "task-b" before retries run out.
    const getTasksByIds = vi.fn(async () => ({
      "task-a": completed(true),
      "task-b": executing,
    }));
    const settled: Array<[string, unknown]> = [];
    const resolveExhausted = vi.fn(async (taskId: string) =>
      taskId === "task-b" ? { status: CONNECTION_CHECK_STATUS.SUCCESS } : null,
    );

    // When
    await pollConnectionTasks(["task-a", "task-b"], {
      onSettled: (taskId, result) => settled.push([taskId, result]),
      getTasksByIds,
      sleep: async () => {},
      maxRetries: 2,
      resolveExhausted,
    });

    // Then: the exhausted task is settled from the fallback, not a timeout.
    expect(resolveExhausted).toHaveBeenCalledWith("task-b");
    expect(settled).toEqual([
      ["task-a", { status: CONNECTION_CHECK_STATUS.SUCCESS }],
      ["task-b", { status: CONNECTION_CHECK_STATUS.SUCCESS }],
    ]);
  });

  it("reports a still-running fallback as pending, not as a failure", async () => {
    // Given: the batch read never settles "task-b", and the caller's fallback
    // cannot confirm an outcome either (the backend task is still running).
    const getTasksByIds = vi.fn(async () => ({
      "task-a": completed(true),
      "task-b": executing,
    }));
    const settled: Array<[string, unknown]> = [];
    const resolveExhausted = vi.fn(async (taskId: string) =>
      taskId === "task-b"
        ? {
            status: CONNECTION_CHECK_STATUS.PENDING,
            error: "The connection test is still running.",
          }
        : null,
    );

    // When
    await pollConnectionTasks(["task-a", "task-b"], {
      onSettled: (taskId, result) => settled.push([taskId, result]),
      getTasksByIds,
      sleep: async () => {},
      maxRetries: 2,
      resolveExhausted,
    });

    // Then: pending, distinct from both success and failure.
    expect(settled).toEqual([
      ["task-a", { status: CONNECTION_CHECK_STATUS.SUCCESS }],
      [
        "task-b",
        {
          status: CONNECTION_CHECK_STATUS.PENDING,
          error: "The connection test is still running.",
        },
      ],
    ]);
  });

  it("falls back to the timeout message when the fallback cannot resolve a task", async () => {
    // Given
    const getTasksByIds = vi.fn(async () => ({
      "task-a": completed(true),
      "task-b": executing,
    }));
    const settled: Array<[string, unknown]> = [];
    const resolveExhausted = vi.fn(async () => null);

    // When
    await pollConnectionTasks(["task-a", "task-b"], {
      onSettled: (taskId, result) => settled.push([taskId, result]),
      getTasksByIds,
      sleep: async () => {},
      maxRetries: 2,
      resolveExhausted,
    });

    // Then
    expect(settled).toEqual([
      ["task-a", { status: CONNECTION_CHECK_STATUS.SUCCESS }],
      [
        "task-b",
        {
          status: CONNECTION_CHECK_STATUS.FAILED,
          error: "Connection test timed out.",
        },
      ],
    ]);
  });

  it("surfaces a per-task read failure without touching the rest of the batch", async () => {
    // Given — the batch read reports one task's failure under its own key.
    const getTasksByIds = vi.fn(async () => ({
      "task-a": completed(true),
      "task-b": { error: "Task not found." },
    }));
    const settled: Array<[string, unknown]> = [];

    // When
    await pollConnectionTasks(["task-a", "task-b"], {
      onSettled: (taskId, result) => settled.push([taskId, result]),
      getTasksByIds,
      sleep: async () => {},
      maxRetries: 5,
    });

    // Then
    expect(getTasksByIds).toHaveBeenCalledTimes(1);
    expect(settled).toEqual([
      ["task-a", { status: CONNECTION_CHECK_STATUS.SUCCESS }],
      [
        "task-b",
        { status: CONNECTION_CHECK_STATUS.FAILED, error: "Task not found." },
      ],
    ]);
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
