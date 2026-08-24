import { describe, expect, it, vi } from "vitest";

import { render } from "@/__tests__/render-browser";

const { refreshAccessMock } = vi.hoisted(() => ({
  refreshAccessMock: vi.fn(),
}));
vi.mock("@/actions/registry/registry", () => ({
  refreshRegistryEligibility: refreshAccessMock,
}));

import {
  RegistryEligibilityProvider,
  useRegistryEligibility,
} from "./registry-eligibility-provider";

function Probe() {
  const { isEligible, status } = useRegistryEligibility();
  return <p>{isEligible ? "eligible" : status}</p>;
}

const renderProbe = () =>
  render(
    <RegistryEligibilityProvider>
      <Probe />
    </RegistryEligibilityProvider>,
  );

describe("RegistryEligibilityProvider", () => {
  it("requires a server lease, renews visible access, and expires hidden access", async () => {
    // Given
    vi.useFakeTimers();
    refreshAccessMock.mockResolvedValue({
      status: "eligible",
      leaseDurationMs: 30_000,
    });
    const view = await renderProbe();
    await expect.element(view.getByText("eligible")).toBeVisible();

    // When
    await vi.advanceTimersByTimeAsync(15_000);
    Object.defineProperty(document, "visibilityState", {
      configurable: true,
      value: "hidden",
    });
    await vi.advanceTimersByTimeAsync(30_000);

    // Then
    expect(refreshAccessMock).toHaveBeenCalledTimes(2);
    await expect.element(view.getByText("unknown")).toBeVisible();
    vi.useRealTimers();
    Object.defineProperty(document, "visibilityState", {
      configurable: true,
      value: "visible",
    });
  });

  it("rejects a late lease after a newer foreground denial", async () => {
    // Given
    let resolveFirst!: (value: unknown) => void;
    refreshAccessMock
      .mockImplementationOnce(
        () =>
          new Promise<unknown>((resolve) => {
            resolveFirst = resolve;
          }),
      )
      .mockResolvedValueOnce({ status: "ineligible" });
    const view = await renderProbe();

    // When
    window.dispatchEvent(new Event("focus"));
    resolveFirst!({ status: "eligible", leaseDurationMs: 30_000 });

    // Then
    await expect.element(view.getByText("ineligible")).toBeVisible();
  });
});
