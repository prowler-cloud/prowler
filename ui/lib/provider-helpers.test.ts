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
  const CHECK_STARTED_AT = "2026-01-01T00:00:00.000Z";

  it("trusts a stored connected=true only once it postdates the check", async () => {
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

    expect(
      await resolveProviderConnectionState("account", CHECK_STARTED_AT),
    ).toEqual({ status: CONNECTION_CHECK_STATUS.SUCCESS, error: null });
  });

  it("treats a stale connected=true as pending, not success", async () => {
    // Given: a provider was connected from a previous check (e.g. before the
    // user swapped in bad credentials), and this check is still running.
    getProvider.mockResolvedValue({
      data: {
        attributes: {
          connection: {
            connected: true,
            last_checked_at: "2025-12-31T23:59:59.000Z",
          },
        },
      },
    });

    const result = await resolveProviderConnectionState(
      "account",
      CHECK_STARTED_AT,
    );

    expect(result.status).toBe(CONNECTION_CHECK_STATUS.PENDING);
    expect(result.error).toMatch(/still running/i);
  });

  it("treats a missing last_checked_at as pending even when connected is true", async () => {
    getProvider.mockResolvedValue({
      data: {
        attributes: {
          connection: { connected: true, last_checked_at: null },
        },
      },
    });

    const result = await resolveProviderConnectionState(
      "account",
      CHECK_STARTED_AT,
    );

    expect(result.status).toBe(CONNECTION_CHECK_STATUS.PENDING);
  });

  it("reports a current connected=false as a confirmed failure", async () => {
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

    const result = await resolveProviderConnectionState(
      "account",
      CHECK_STARTED_AT,
    );

    expect(result).toEqual({
      status: CONNECTION_CHECK_STATUS.FAILED,
      error: expect.stringMatching(/test the connection again/i),
    });
  });
});

describe("provider connection confirmation", () => {
  beforeEach(() => {
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

    it("reports success when the stored state was written after this check began", async () => {
      getProvider.mockResolvedValue({
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
      // Given: the provider was connected from a previous check, credentials
      // just changed, and this check is still running past the wait.
      getProvider.mockResolvedValue({
        data: {
          attributes: {
            connection: {
              connected: true,
              last_checked_at: "2000-01-01T00:00:00Z",
            },
          },
        },
      });

      const result = await testProviderConnection("account");

      expect(result.status).not.toBe(CONNECTION_CHECK_STATUS.SUCCESS);
      expect(result.status).toBe(CONNECTION_CHECK_STATUS.PENDING);
    });

    it("reports the failure when the provider is confirmed not connected by this check", async () => {
      getProvider.mockResolvedValue({
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

  it("does not fall back to provider state for a real task failure", async () => {
    checkTaskStatus.mockResolvedValue({
      completed: false,
      error: "Unexpected task state",
    });

    const result = await testProviderConnection("account");

    expect(getProvider).not.toHaveBeenCalled();
    expect(result).toEqual({
      status: CONNECTION_CHECK_STATUS.FAILED,
      error: "Unexpected task state",
    });
  });
});
