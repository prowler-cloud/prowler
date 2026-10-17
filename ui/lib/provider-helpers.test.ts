import { beforeEach, describe, expect, it, vi } from "vitest";

const { checkConnectionProvider, checkTaskStatus, getProvider } = vi.hoisted(
  () => ({
    checkConnectionProvider: vi.fn(),
    checkTaskStatus: vi.fn(),
    getProvider: vi.fn(),
  }),
);
vi.mock("@/actions/providers/providers", () => ({
  checkConnectionProvider,
  getProvider,
}));
vi.mock("./helper", () => ({
  checkTaskStatus,
  TASK_STATUS_MAX_RETRIES_ERROR: "Max retries exceeded",
}));

import {
  CONNECTION_CHECK_STATUS,
  PROVIDER_CONNECTION_CHECK_MAX_RETRIES,
  PROVIDER_CONNECTION_CHECK_POLL_DELAY_MS,
  resolveProviderConnectionState,
  testProviderConnection,
} from "./provider-helpers";

describe("resolveProviderConnectionState", () => {
  it("trusts a stored connected=true once last_checked_at differs from the baseline", async () => {
    getProvider.mockResolvedValue({
      data: {
        attributes: {
          connection: {
            connected: true,
            last_checked_at: "2026-01-01T00:00:10.000Z",
          },
        },
      },
    });

    expect(await resolveProviderConnectionState("account", null)).toEqual({
      status: CONNECTION_CHECK_STATUS.SUCCESS,
      error: null,
    });
  });

  it("treats a stored connected=true as pending while last_checked_at still matches the baseline", async () => {
    // Given: the provider was connected from a previous check, and this check --
    // dispatched after that baseline was captured -- is still running.
    const baseline = "2025-12-31T23:59:59.000Z";
    getProvider.mockResolvedValue({
      data: {
        attributes: {
          connection: { connected: true, last_checked_at: baseline },
        },
      },
    });

    const result = await resolveProviderConnectionState("account", baseline);

    expect(result.status).toBe(CONNECTION_CHECK_STATUS.PENDING);
    expect(result.error).toMatch(/still running/i);
  });

  it("reports success once last_checked_at changes, even when the new value sorts earlier than the baseline", async () => {
    // Given: a deployment whose clocks are not synchronised -- the server writes
    // a `last_checked_at` that, read as a plain string/date, sorts *before* the
    // baseline captured moments earlier from the same server. A timestamp
    // comparison would misread this as stale; a value comparison does not.
    const baseline = "2026-06-01T00:00:00.000Z";
    getProvider.mockResolvedValue({
      data: {
        attributes: {
          connection: {
            connected: true,
            last_checked_at: "2020-01-01T00:00:00.000Z",
          },
        },
      },
    });

    const result = await resolveProviderConnectionState("account", baseline);

    expect(result).toEqual({
      status: CONNECTION_CHECK_STATUS.SUCCESS,
      error: null,
    });
  });

  it("treats a missing last_checked_at as pending even when connected is true", async () => {
    getProvider.mockResolvedValue({
      data: {
        attributes: {
          connection: { connected: true, last_checked_at: null },
        },
      },
    });

    const result = await resolveProviderConnectionState("account", null);

    expect(result.status).toBe(CONNECTION_CHECK_STATUS.PENDING);
  });

  it("treats an unknown baseline as unresolved, never trusting a pre-existing stored result", async () => {
    // Given: the pre-dispatch baseline read failed, so there is nothing to
    // compare this result against.
    getProvider.mockResolvedValue({
      data: {
        attributes: {
          connection: {
            connected: true,
            last_checked_at: "2026-01-01T00:00:10.000Z",
          },
        },
      },
    });

    const result = await resolveProviderConnectionState("account", undefined);

    expect(result.status).toBe(CONNECTION_CHECK_STATUS.PENDING);
  });

  it("reports a changed connected=false as a confirmed failure", async () => {
    getProvider.mockResolvedValue({
      data: {
        attributes: {
          connection: {
            connected: false,
            last_checked_at: "2026-01-01T00:00:10.000Z",
          },
        },
      },
    });

    const result = await resolveProviderConnectionState("account", null);

    expect(result).toEqual({
      status: CONNECTION_CHECK_STATUS.FAILED,
      error: expect.stringMatching(/test the connection again/i),
    });
  });
});

describe("provider connection confirmation", () => {
  beforeEach(() => {
    // The baseline read (before dispatch) and the exhausted-wait fallback read
    // both go through `getProvider`; default to "no prior check" unless a test
    // overrides it.
    getProvider.mockResolvedValue({
      data: {
        attributes: { connection: { connected: null, last_checked_at: null } },
      },
    });
    checkConnectionProvider.mockResolvedValue({ data: { id: "task" } });
  });
  it.each([undefined, {}, { connected: "true" }, { connected: false }])(
    "does not advance without explicit connected=true: %j",
    async (result) => {
      checkTaskStatus.mockResolvedValue({
        completed: true,
        task: { data: { attributes: { result } } },
      });
      expect((await testProviderConnection("account")).status).toBe(
        CONNECTION_CHECK_STATUS.FAILED,
      );
    },
  );
  it("advances on an explicitly successful connection", async () => {
    checkTaskStatus.mockResolvedValue({
      completed: true,
      task: { data: { attributes: { result: { connected: true } } } },
    });
    expect(await testProviderConnection("account")).toEqual({
      status: CONNECTION_CHECK_STATUS.SUCCESS,
      error: null,
    });
  });

  it("reads the baseline before dispatching the check", async () => {
    checkTaskStatus.mockResolvedValue({
      completed: true,
      task: { data: { attributes: { result: { connected: true } } } },
    });

    const callOrder: string[] = [];
    getProvider.mockImplementation(async () => {
      callOrder.push("getProvider");
      return {
        data: {
          attributes: {
            connection: { connected: null, last_checked_at: null },
          },
        },
      };
    });
    checkConnectionProvider.mockImplementation(async () => {
      callOrder.push("checkConnectionProvider");
      return { data: { id: "task" } };
    });

    await testProviderConnection("account");

    expect(callOrder).toEqual(["getProvider", "checkConnectionProvider"]);
  });

  it("sizes the wait past the backend's 120s provider-connection-check time limit", async () => {
    checkTaskStatus.mockResolvedValue({
      completed: true,
      task: { data: { attributes: { result: { connected: true } } } },
    });

    await testProviderConnection("account");

    expect(checkTaskStatus).toHaveBeenCalledWith(
      "task",
      PROVIDER_CONNECTION_CHECK_MAX_RETRIES,
      PROVIDER_CONNECTION_CHECK_POLL_DELAY_MS,
    );
    expect(
      PROVIDER_CONNECTION_CHECK_MAX_RETRIES *
        PROVIDER_CONNECTION_CHECK_POLL_DELAY_MS,
    ).toBeGreaterThan(120_000);
  });

  describe("when the wait is exhausted", () => {
    beforeEach(() => {
      checkTaskStatus.mockResolvedValue({
        completed: false,
        error: "Max retries exceeded",
      });
    });

    it("reports success when the stored state changed after the baseline was captured", async () => {
      // Baseline (read before dispatch): no prior check. Fallback read: a fresh
      // result landed while the UI was waiting.
      getProvider
        .mockResolvedValueOnce({
          data: {
            attributes: {
              connection: { connected: null, last_checked_at: null },
            },
          },
        })
        .mockResolvedValueOnce({
          data: {
            attributes: {
              connection: {
                connected: true,
                last_checked_at: "2999-01-01T00:00:00Z",
              },
            },
          },
        });

      expect(await testProviderConnection("account")).toEqual({
        status: CONNECTION_CHECK_STATUS.SUCCESS,
        error: null,
      });
    });

    it("does not report success from a stale stored result predating this check", async () => {
      // Given: the provider was already connected from a previous check --
      // captured as the baseline before this check was dispatched -- and the
      // fallback read comes back with that exact same (unchanged) value,
      // meaning the new check has not written a result yet.
      const priorLastCheckedAt = "2025-06-01T00:00:00Z";
      getProvider.mockResolvedValue({
        data: {
          attributes: {
            connection: {
              connected: true,
              last_checked_at: priorLastCheckedAt,
            },
          },
        },
      });

      const result = await testProviderConnection("account");

      expect(result.status).not.toBe(CONNECTION_CHECK_STATUS.SUCCESS);
      expect(result.status).toBe(CONNECTION_CHECK_STATUS.PENDING);
    });

    it("reports pending, not connected, when the browser clock is behind the server and the stored result predates the check", async () => {
      // Given: a deployment whose clocks are not synchronised -- the browser's
      // clock is behind the server's. Under a clock-based comparison this could
      // make an older stored result look newer than the check's start and be
      // reported as connected. The baseline here is captured from the server's
      // own prior value, so the comparison never depends on the browser's clock
      // at all: an unchanged value is still unchanged.
      const staleServerTimestamp = "2026-03-01T12:00:00Z";
      getProvider.mockResolvedValue({
        data: {
          attributes: {
            connection: {
              connected: true,
              last_checked_at: staleServerTimestamp,
            },
          },
        },
      });

      const result = await testProviderConnection("account");

      expect(result.status).toBe(CONNECTION_CHECK_STATUS.PENDING);
      expect(result.status).not.toBe(CONNECTION_CHECK_STATUS.SUCCESS);
    });

    it("reports the failure when the provider is confirmed not connected by this check", async () => {
      getProvider
        .mockResolvedValueOnce({
          data: {
            attributes: {
              connection: { connected: null, last_checked_at: null },
            },
          },
        })
        .mockResolvedValueOnce({
          data: {
            attributes: {
              connection: {
                connected: false,
                last_checked_at: "2999-01-01T00:00:00Z",
              },
            },
          },
        });

      const result = await testProviderConnection("account");

      expect(result.status).toBe(CONNECTION_CHECK_STATUS.FAILED);
      expect(result.error).toMatch(/test the connection again/i);
    });

    it("shows a neutral still-checking message when the provider state is undetermined", async () => {
      getProvider.mockResolvedValue({
        data: {
          attributes: {
            connection: { connected: null, last_checked_at: null },
          },
        },
      });

      const result = await testProviderConnection("account");

      expect(result.status).toBe(CONNECTION_CHECK_STATUS.PENDING);
      expect(result.error).toMatch(/still running|refresh/i);
      expect(result.error?.toLowerCase()).not.toContain("error");
      expect(result.error?.toLowerCase()).not.toContain("failed");
    });
  });

  it("does not re-read provider state for a real task failure", async () => {
    checkTaskStatus.mockResolvedValue({
      completed: false,
      error: "Unexpected task state",
    });

    const result = await testProviderConnection("account");

    // The baseline read (before dispatch) still happens, but nothing reads
    // provider state again to resolve this failure.
    expect(getProvider).toHaveBeenCalledTimes(1);
    expect(result).toEqual({
      status: CONNECTION_CHECK_STATUS.FAILED,
      error: "Unexpected task state",
    });
  });
});
