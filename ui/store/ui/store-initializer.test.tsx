import { render } from "@testing-library/react";
import { beforeEach, describe, expect, it } from "vitest";

import { useUIStore } from "./store";
import { StoreInitializer } from "./store-initializer";

describe("StoreInitializer", () => {
  beforeEach(() => {
    localStorage.clear();
    useUIStore.setState({ hasProviders: false, registryEligible: false });
  });

  it("seeds the server-derived Registry eligibility into the UI store", () => {
    // Given / When
    render(<StoreInitializer values={{ registryEligible: true }} />);

    // Then
    expect(useUIStore.getState().registryEligible).toBe(true);
  });

  it("keeps Registry hidden when the server sends no eligibility decision", () => {
    // Given / When
    render(<StoreInitializer values={{ hasProviders: true }} />);

    // Then
    expect(useUIStore.getState().registryEligible).toBe(false);
    expect(useUIStore.getState().hasProviders).toBe(true);
  });

  it("never persists Registry eligibility across sessions", () => {
    // Given / When
    render(
      <StoreInitializer
        values={{ hasProviders: true, registryEligible: true }}
      />,
    );

    // Then
    const persisted = JSON.parse(localStorage.getItem("ui-store") ?? "{}");
    expect(persisted.state?.hasProviders).toBe(true);
    expect(persisted.state).not.toHaveProperty("registryEligible");
  });
});
