import { beforeEach, describe, expect, it, vi } from "vitest";

const { checkConnectionProvider, checkTaskStatus } = vi.hoisted(() => ({
  checkConnectionProvider: vi.fn(),
  checkTaskStatus: vi.fn(),
}));
vi.mock("@/actions/providers/providers", () => ({ checkConnectionProvider }));
vi.mock("./helper", () => ({ checkTaskStatus }));

import { testProviderConnection } from "./provider-helpers";

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
});
