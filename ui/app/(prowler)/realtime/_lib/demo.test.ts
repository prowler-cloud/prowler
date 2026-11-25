import { describe, expect, it } from "vitest";

import { isRealtimeDemo } from "./demo";
import { DEFAULT_REALTIME_POLICY } from "./policy-schema";

describe("isRealtimeDemo", () => {
  it("shows demo data only while the account has no policy", () => {
    expect(isRealtimeDemo(null)).toBe(true);
  });

  it("keeps a paused account on its own data", () => {
    expect(
      isRealtimeDemo({
        ...DEFAULT_REALTIME_POLICY,
        id: "policy",
        provider_id: "provider",
        enabled: false,
      }),
    ).toBe(false);
  });
});
