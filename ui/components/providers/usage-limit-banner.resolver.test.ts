import { describe, expect, it } from "vitest";

import { shouldDisplayUsageLimitBanner } from "./usage-limit-banner.resolver";

describe("shouldDisplayUsageLimitBanner", () => {
  it("fails closed for deployments without a private billing resolver", async () => {
    await expect(shouldDisplayUsageLimitBanner()).resolves.toBe(false);
  });
});
