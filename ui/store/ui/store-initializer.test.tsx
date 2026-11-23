import { render } from "@testing-library/react";
import { beforeEach, describe, expect, it } from "vitest";

import { useUIStore } from "./store";
import { StoreInitializer } from "./store-initializer";

describe("StoreInitializer", () => {
  beforeEach(() => {
    localStorage.clear();
    useUIStore.setState({
      hasProviders: false,
      hasProvidersResolved: false,
      registryEligible: false,
    });
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
    expect(useUIStore.getState().registryEligible).toBe(true);
    const persisted = JSON.parse(localStorage.getItem("ui-store") ?? "{}");
    expect(persisted.state?.hasProviders).toBe(true);
    expect(persisted.state).not.toHaveProperty("registryEligible");
  });

  it("leaves the provider count unresolved when the server could not determine it", () => {
    // Given / When
    render(<StoreInitializer values={{ hasProviders: undefined }} />);

    // Then
    expect(useUIStore.getState().hasProvidersResolved).toBe(false);
  });

  it("resolves a confirmed empty tenant without persisting the resolution", () => {
    // Given / When
    render(<StoreInitializer values={{ hasProviders: false }} />);

    // Then
    expect(useUIStore.getState().hasProviders).toBe(false);
    expect(useUIStore.getState().hasProvidersResolved).toBe(true);
    const persisted = JSON.parse(localStorage.getItem("ui-store") ?? "{}");
    expect(persisted.state).not.toHaveProperty("hasProvidersResolved");
  });
});
