import { describe, expect, it } from "vitest";

import { PROVIDER_DISPLAY_NAMES } from "@/types/providers";

import { getProviderBadge, getProviderLabel } from "./provider-display";

describe("getProviderBadge", () => {
  it("resolves a badge for every provider added to close the CIS Controls 8.1 icon gap", () => {
    // github/googleworkspace/okta/cloudflare/mongodbatlas/openstack/vercel
    // were previously missing from PROVIDER_BADGE_BY_KEY, rendering blank
    // squares wherever a badge was expected.
    const withIcons = [
      "github",
      "googleworkspace",
      "okta",
      "cloudflare",
      "mongodbatlas",
      "openstack",
      "vercel",
    ];
    for (const key of withIcons) {
      expect(getProviderBadge(key), key).toBeDefined();
    }
  });

  it("returns undefined for providers that only have a fallback label", () => {
    // linode/stackit/nhn/scaleway are declared by the SDK's universal
    // compliance templates but have no dedicated icon component yet —
    // ProviderBadgeIcon depends on this returning undefined to know when
    // to render its initials fallback instead.
    for (const key of ["linode", "stackit", "nhn", "scaleway"]) {
      expect(getProviderBadge(key), key).toBeUndefined();
    }
  });

  it("returns undefined for an entirely unknown provider key", () => {
    expect(getProviderBadge("made-up-provider")).toBeUndefined();
  });
});

describe("getProviderLabel", () => {
  it("reuses the shared PROVIDER_DISPLAY_NAMES map instead of a divergent local copy", () => {
    // Regression guard: an earlier version of this module hand-copied
    // labels and drifted from types/providers.ts (e.g. "GCP" vs "Google
    // Cloud", "Oracle Cloud" vs "Oracle Cloud Infrastructure"), producing a
    // different label for the same provider on different parts of the same
    // page. Every known ProviderType must match the shared map exactly.
    for (const [key, label] of Object.entries(PROVIDER_DISPLAY_NAMES)) {
      expect(getProviderLabel(key), key).toBe(label);
    }
  });

  it("labels backend-only providers not yet onboarded as a ProviderType", () => {
    expect(getProviderLabel("linode")).toBe("Linode");
    expect(getProviderLabel("stackit")).toBe("STACKIT");
    expect(getProviderLabel("nhn")).toBe("NHN Cloud");
    expect(getProviderLabel("scaleway")).toBe("Scaleway");
  });

  it("falls back to the uppercased key for an entirely unknown provider", () => {
    expect(getProviderLabel("made-up-provider")).toBe("MADE-UP-PROVIDER");
  });
});
