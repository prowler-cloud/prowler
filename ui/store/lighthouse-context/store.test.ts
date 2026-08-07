import { beforeEach, describe, expect, it } from "vitest";

import { useLighthouseContextStore } from "./store";
import { resetLighthouseContextStore } from "./store.test-utils";

describe("useLighthouseContextStore", () => {
  beforeEach(() => {
    resetLighthouseContextStore();
  });

  it("should replace a contribution when an interaction updates it", () => {
    // Given
    const { registerContribution } = useLighthouseContextStore.getState();
    registerContribution("selected-resource", {
      kind: "resource",
      id: "resource-1",
      source: "selection",
      scopeKey: "resources:/resources",
      label: "Selected resource",
      resourceId: "resource-1",
    });

    // When
    registerContribution("selected-resource", {
      kind: "resource",
      id: "resource-2",
      source: "selection",
      scopeKey: "resources:/resources",
      label: "Selected resource",
      resourceId: "resource-2",
    });

    // Then
    expect(
      Object.values(useLighthouseContextStore.getState().contributions).map(
        (item) => item.id,
      ),
    ).toEqual(["resource-2"]);
  });

  it("should keep focused context owned by the latest detail panel", () => {
    // Given
    const { setFocusedContext, clearFocusedContext } =
      useLighthouseContextStore.getState();
    setFocusedContext(1, {
      kind: "finding",
      id: "finding-1",
      source: "focused",
      scopeKey: "findings:/findings",
      label: "Focused finding",
      findingId: "finding-1",
    });

    // When
    setFocusedContext(2, {
      kind: "resource",
      id: "resource-2",
      source: "focused",
      scopeKey: "resources:/resources",
      label: "Focused resource",
      resourceId: "resource-2",
    });
    clearFocusedContext(1);

    // Then
    expect(useLighthouseContextStore.getState().focused?.id).toBe("resource-2");

    // When
    clearFocusedContext(2);

    // Then
    expect(useLighthouseContextStore.getState().focused).toBeNull();
  });

  it("should reject focus updates from an older detail panel", () => {
    // Given
    const { clearFocusedContext, setFocusedContext } =
      useLighthouseContextStore.getState();
    setFocusedContext(2, {
      kind: "resource",
      id: "resource-2",
      source: "focused",
      scopeKey: "resources:/resources",
      label: "Focused resource",
      resourceId: "resource-2",
    });

    // When
    setFocusedContext(1, {
      kind: "finding",
      id: "stale-finding",
      source: "focused",
      scopeKey: "findings:/findings",
      label: "Stale focused finding",
      findingId: "stale-finding",
    });

    // Then
    expect(useLighthouseContextStore.getState().focused?.id).toBe("resource-2");
    expect(useLighthouseContextStore.getState().focusedOwnerToken).toBe(2);

    // When
    clearFocusedContext(2);
    setFocusedContext(1, {
      kind: "finding",
      id: "stale-finding-after-clear",
      source: "focused",
      scopeKey: "findings:/findings",
      label: "Stale focused finding after clear",
      findingId: "stale-finding-after-clear",
    });

    // Then
    expect(useLighthouseContextStore.getState().focused).toBeNull();
    expect(useLighthouseContextStore.getState().focusedOwnerToken).toBe(2);
  });
});
