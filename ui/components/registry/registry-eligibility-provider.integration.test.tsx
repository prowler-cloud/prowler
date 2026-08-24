import { act } from "react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

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
  const { invalidate, isEligible, status } = useRegistryEligibility();
  return (
    <>
      <p>{isEligible ? "eligible" : status}</p>
      <button type="button" onClick={invalidate}>
        Invalidate Registry eligibility
      </button>
    </>
  );
}

const renderProbe = () =>
  render(
    <RegistryEligibilityProvider>
      <Probe />
    </RegistryEligibilityProvider>,
  );

describe("RegistryEligibilityProvider", () => {
  beforeEach(() => {
    refreshAccessMock.mockReset();
  });

  afterEach(() => {
    vi.useRealTimers();
    Object.defineProperty(document, "visibilityState", {
      configurable: true,
      value: "visible",
    });
  });

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
    await act(async () => {
      await vi.advanceTimersByTimeAsync(15_000);
    });
    Object.defineProperty(document, "visibilityState", {
      configurable: true,
      value: "hidden",
    });
    await act(async () => {
      await vi.advanceTimersByTimeAsync(30_000);
    });

    // Then
    expect(refreshAccessMock).toHaveBeenCalledTimes(2);
    await expect.element(view.getByText("unknown")).toBeVisible();
    vi.useRealTimers();
    Object.defineProperty(document, "visibilityState", {
      configurable: true,
      value: "visible",
    });
  });

  it("renews visible eligibility continuously beyond sixty seconds", async () => {
    // Given
    vi.useFakeTimers();
    refreshAccessMock.mockResolvedValue({
      status: "eligible",
      leaseDurationMs: 30_000,
    });
    const view = await renderProbe();
    await expect.element(view.getByText("eligible")).toBeVisible();

    // When
    for (let renewal = 0; renewal < 5; renewal += 1) {
      await act(async () => {
        await vi.advanceTimersByTimeAsync(15_000);
      });
    }

    // Then
    expect(refreshAccessMock).toHaveBeenCalledTimes(6);
    await expect.element(view.getByText("eligible")).toBeVisible();
  });

  it("preserves an unexpired eligible lease after a routine network failure", async () => {
    // Given
    vi.useFakeTimers();
    refreshAccessMock
      .mockResolvedValueOnce({ status: "eligible", leaseDurationMs: 30_000 })
      .mockRejectedValueOnce(new Error("network unavailable"));
    const view = await renderProbe();
    await expect.element(view.getByText("eligible")).toBeVisible();

    // When
    await act(async () => {
      await vi.advanceTimersByTimeAsync(15_000);
    });

    // Then
    await expect.element(view.getByText("eligible")).toBeVisible();

    // When
    await act(async () => {
      await vi.advanceTimersByTimeAsync(15_000);
    });

    // Then
    await expect.element(view.getByText("unknown")).toBeVisible();
  });

  it("preserves an unexpired eligible lease after a routine unknown result", async () => {
    // Given
    vi.useFakeTimers();
    refreshAccessMock
      .mockResolvedValueOnce({ status: "eligible", leaseDurationMs: 30_000 })
      .mockResolvedValueOnce({ status: "unknown" });
    const view = await renderProbe();
    await expect.element(view.getByText("eligible")).toBeVisible();

    // When
    await act(async () => {
      await vi.advanceTimersByTimeAsync(15_000);
    });

    // Then
    await expect.element(view.getByText("eligible")).toBeVisible();

    // When
    await act(async () => {
      await vi.advanceTimersByTimeAsync(15_000);
    });

    // Then
    await expect.element(view.getByText("unknown")).toBeVisible();
  });

  it("denies a routine foreground recheck immediately when access is ineligible", async () => {
    // Given
    refreshAccessMock
      .mockResolvedValueOnce({ status: "eligible", leaseDurationMs: 30_000 })
      .mockResolvedValueOnce({ status: "ineligible" });
    const view = await renderProbe();
    await expect.element(view.getByText("eligible")).toBeVisible();

    // When
    window.dispatchEvent(new Event("focus"));

    // Then
    await expect.element(view.getByText("ineligible")).toBeVisible();
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

  it("fails closed immediately after explicit authorization invalidation", async () => {
    // Given
    refreshAccessMock.mockResolvedValue({
      status: "eligible",
      leaseDurationMs: 30_000,
    });
    const view = await renderProbe();
    await expect.element(view.getByText("eligible")).toBeVisible();

    // When
    await view
      .getByRole("button", { name: "Invalidate Registry eligibility" })
      .click();

    // Then
    await expect.element(view.getByText("ineligible")).toBeVisible();
  });
});
