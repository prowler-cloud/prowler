import { describe, expect, it, vi } from "vitest";

import { render } from "@/__tests__/render-browser";

vi.mock("@/lib/registry/access.server", () => ({
  refreshRegistryEligibility: () => Promise.resolve({ status: "ineligible" }),
}));

import { RegistryAccessBoundary } from "./registry-access-boundary";
import { RegistryEligibilityProvider } from "./registry-eligibility-provider";

describe("RegistryAccessBoundary", () => {
  it("unmounts protected Registry state after client access denial", async () => {
    // Given / When
    await render(
      <RegistryEligibilityProvider>
        <RegistryAccessBoundary initialLeaseDurationMs={30_000}>
          <p>Protected Registry state</p>
        </RegistryAccessBoundary>
      </RegistryEligibilityProvider>,
    );

    // Then
    await expect
      .poll(() => document.body.textContent)
      .not.toContain("Protected Registry state");
  });
});
