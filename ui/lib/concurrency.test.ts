import { describe, expect, it } from "vitest";

import { runWithConcurrencyLimit } from "./concurrency";

describe("runWithConcurrencyLimit", () => {
  it("should process items without exceeding the configured concurrency", async () => {
    // Given
    const items = Array.from({ length: 12 }, (_, index) => index + 1);
    let activeTasks = 0;
    let maxActiveTasks = 0;

    // When
    const results = await runWithConcurrencyLimit(items, 4, async (item) => {
      activeTasks += 1;
      maxActiveTasks = Math.max(maxActiveTasks, activeTasks);
      await new Promise((resolve) => setTimeout(resolve, 5));
      activeTasks -= 1;
      return item * 2;
    });

    // Then
    expect(maxActiveTasks).toBeLessThanOrEqual(4);
    expect(results).toEqual(items.map((item) => item * 2));
  });

  it("should reject when worker throws an uncaught error", async () => {
    // Given
    const items = [1, 2, 3];

    // When / Then
    await expect(
      runWithConcurrencyLimit(items, 2, async (item) => {
        if (item === 2) {
          throw new Error("boom");
        }
        return item;
      }),
    ).rejects.toThrow("boom");
  });
});
