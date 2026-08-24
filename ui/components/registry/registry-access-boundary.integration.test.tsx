import { act } from "react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { render } from "@/__tests__/render-browser";

const { refreshAccessMock } = vi.hoisted(() => ({
  refreshAccessMock: vi.fn(),
}));
vi.mock("@/actions/registry/registry", () => ({
  refreshRegistryEligibility: refreshAccessMock,
}));

import { RegistryAccessBoundary } from "./registry-access-boundary";
import {
  RegistryEligibilityProvider,
  useRegistryEligibility,
} from "./registry-eligibility-provider";

function EligibilityProbe() {
  const { generation, isEligible, status } = useRegistryEligibility();
  return (
    <p>{`${isEligible ? "eligible" : status} generation ${generation}`}</p>
  );
}

describe("RegistryAccessBoundary", () => {
  beforeEach(() => {
    refreshAccessMock.mockReset();
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it("unmounts protected Registry state after client access denial", async () => {
    // Given
    refreshAccessMock.mockResolvedValue({ status: "ineligible" });

    // When
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

  it("keeps protected Registry state mounted during an unexpired server lease", async () => {
    // Given
    refreshAccessMock.mockImplementation(() => new Promise(() => {}));
    const view = await render(
      <RegistryEligibilityProvider>
        <EligibilityProbe />
        <RegistryAccessBoundary initialLeaseDurationMs={30_000}>
          <p>Protected Registry state</p>
        </RegistryAccessBoundary>
      </RegistryEligibilityProvider>,
    );
    await expect
      .element(view.getByText("Protected Registry state"))
      .toBeVisible();

    // When
    window.dispatchEvent(new Event("focus"));
    await expect.poll(() => refreshAccessMock).toHaveBeenCalledTimes(2);

    // Then
    await expect.element(view.getByText("unknown generation 0")).toBeVisible();
    await expect
      .element(view.getByText("Protected Registry state"))
      .toBeVisible();
  });

  it("keeps protected Registry state mounted when a routine recheck outlasts the server lease", async () => {
    // Given
    vi.useFakeTimers();
    refreshAccessMock
      .mockResolvedValueOnce({ status: "eligible", leaseDurationMs: 60_000 })
      .mockImplementation(() => new Promise(() => {}));
    const view = await render(
      <RegistryEligibilityProvider>
        <RegistryAccessBoundary initialLeaseDurationMs={30_000}>
          <p>Protected Registry state</p>
        </RegistryAccessBoundary>
      </RegistryEligibilityProvider>,
    );
    await expect
      .element(view.getByText("Protected Registry state"))
      .toBeVisible();

    // When
    window.dispatchEvent(new Event("focus"));
    await expect.poll(() => refreshAccessMock).toHaveBeenCalledTimes(2);
    await act(async () => {
      await vi.advanceTimersByTimeAsync(30_000);
    });

    // Then
    await expect
      .element(view.getByText("Protected Registry state"))
      .toBeVisible();
  });

  it("fails closed after the initial unknown state reaches the bounded server lease", async () => {
    // Given
    vi.useFakeTimers();
    refreshAccessMock.mockImplementation(() => new Promise(() => {}));
    const view = await render(
      <RegistryEligibilityProvider>
        <RegistryAccessBoundary initialLeaseDurationMs={30_000}>
          <p>Protected Registry state</p>
        </RegistryAccessBoundary>
      </RegistryEligibilityProvider>,
    );
    await expect
      .element(view.getByText("Protected Registry state"))
      .toBeVisible();

    // When
    await act(async () => {
      await vi.advanceTimersByTimeAsync(30_000);
    });

    // Then
    expect(document.body.textContent).not.toContain("Protected Registry state");
  });
});
