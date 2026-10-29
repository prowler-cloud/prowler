import { describe, expect, it } from "vitest";

import {
  DEMO_ANOMALY_ID,
  demoAnomalyHref,
  isRealtimeDemoMode,
  setupHref,
} from "./demo";
import { anomalyHref, parseAnomalyId } from "./display";

describe("isRealtimeDemoMode", () => {
  it("is a demo with no AWS provider at all", () => {
    expect(isRealtimeDemoMode({ providerId: undefined, policy: null })).toBe(
      true,
    );
    expect(
      isRealtimeDemoMode({ providerId: "", policy: { enabled: true } }),
    ).toBe(true);
  });

  it("is a demo while the provider has no policy or a disabled one", () => {
    expect(isRealtimeDemoMode({ providerId: "p", policy: null })).toBe(true);
    expect(isRealtimeDemoMode({ providerId: "p", policy: undefined })).toBe(
      true,
    );
    expect(
      isRealtimeDemoMode({ providerId: "p", policy: { enabled: false } }),
    ).toBe(true);
  });

  it("shows the account's own data once the policy is enabled", () => {
    expect(
      isRealtimeDemoMode({ providerId: "p", policy: { enabled: true } }),
    ).toBe(false);
  });
});

describe("demo links", () => {
  it("links the setup wizard with the provider when there is one", () => {
    expect(setupHref()).toBe("/realtime/setup");
    expect(setupHref("a b")).toBe("/realtime/setup?provider=a%20b");
  });

  it("gives the sample anomaly one fixed page", () => {
    expect(demoAnomalyHref()).toBe("/realtime/cost-anomalies/demo");
    expect(demoAnomalyHref("p1")).toBe(
      "/realtime/cost-anomalies/demo?provider=p1",
    );
    expect(anomalyHref(DEMO_ANOMALY_ID, "p1", true)).toBe(
      "/realtime/cost-anomalies/demo?provider=p1",
    );
    expect(anomalyHref(DEMO_ANOMALY_ID, "", true)).toBe(
      "/realtime/cost-anomalies/demo",
    );
  });

  it("keeps real anomaly links as they were", () => {
    expect(anomalyHref("EC2|us-east-1", "p1")).toBe(
      "/realtime/cost-anomalies/EC2%7Cus-east-1?provider=p1",
    );
  });

  it("parses the sample anomaly id", () => {
    expect(parseAnomalyId(DEMO_ANOMALY_ID)).toEqual({
      service: "Amazon Elastic Compute Cloud - Compute",
      region: "us-east-1",
    });
  });
});
