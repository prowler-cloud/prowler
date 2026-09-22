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
  PROVIDER_CONNECTION_CHECK_MAX_RETRIES,
  PROVIDER_CONNECTION_CHECK_POLL_DELAY_MS,
  testProviderConnection,
} from "./provider-helpers";

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
      expect((await testProviderConnection("account")).connected).toBe(false);
    },
  );
  it("advances on an explicitly successful connection", async () => {
    checkTaskStatus.mockResolvedValue({
      completed: true,
      task: { data: { attributes: { result: { connected: true } } } },
    });
    expect(await testProviderConnection("account")).toEqual({
      connected: true,
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

    it("reports success when the provider is already connected", async () => {
      getProvider.mockResolvedValue({
        data: {
          attributes: {
            connection: { connected: true, last_checked_at: "now" },
          },
        },
      });

      expect(await testProviderConnection("account")).toEqual({
        connected: true,
        error: null,
      });
    });

    it("reports the failure when the provider is confirmed not connected", async () => {
      getProvider.mockResolvedValue({
        data: {
          attributes: {
            connection: { connected: false, last_checked_at: "now" },
          },
        },
      });

      const result = await testProviderConnection("account");

      expect(result.connected).toBe(false);
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

      expect(result.connected).toBe(false);
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
      connected: false,
      error: "Unexpected task state",
    });
  });
});
