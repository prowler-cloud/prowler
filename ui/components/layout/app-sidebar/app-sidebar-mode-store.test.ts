import { renderHook } from "@testing-library/react";
import { beforeEach, describe, expect, it } from "vitest";

import {
  migrateAppSidebarState,
  useAppSidebarMode,
  useHydratedAppSidebarMode,
} from "./app-sidebar-mode-store";
import { APP_SIDEBAR_MODE } from "./types";

describe("app sidebar mode store", () => {
  beforeEach(() => {
    localStorage.clear();
    useAppSidebarMode.setState({ mode: APP_SIDEBAR_MODE.BROWSE });
  });

  it("keeps the persisted chat mode while discarding legacy sidebar state", () => {
    // Given
    const legacyState = {
      isOpen: false,
      isHover: true,
      navigationMode: APP_SIDEBAR_MODE.CHAT,
      settings: { disabled: false, isHoverOpen: false },
    };

    // When
    const migrated = migrateAppSidebarState(legacyState);

    // Then
    expect(migrated).toEqual({ mode: APP_SIDEBAR_MODE.CHAT });
    expect(migrated).not.toHaveProperty("isOpen");
    expect(migrated).not.toHaveProperty("settings");
  });

  it("falls back to browse for an invalid persisted mode", () => {
    // Given / When
    const migrated = migrateAppSidebarState({ navigationMode: "invalid" });

    // Then
    expect(migrated).toEqual({ mode: APP_SIDEBAR_MODE.BROWSE });
  });

  it("rehydrates the legacy payload under the existing sidebar key", async () => {
    // Given
    localStorage.setItem(
      "sidebar",
      JSON.stringify({
        state: {
          navigationMode: APP_SIDEBAR_MODE.CHAT,
          isOpen: false,
          isHover: true,
          settings: { disabled: true },
        },
        version: 0,
      }),
    );

    // When
    await useAppSidebarMode.persist.rehydrate();

    // Then
    expect(useAppSidebarMode.getState().mode).toBe(APP_SIDEBAR_MODE.CHAT);
    expect(useAppSidebarMode.getState()).not.toEqual(
      expect.objectContaining({ isOpen: expect.anything() }),
    );
  });

  it("updates the current navigation mode", () => {
    // Given / When
    useAppSidebarMode.getState().setMode(APP_SIDEBAR_MODE.CHAT);

    // Then
    expect(useAppSidebarMode.getState().mode).toBe(APP_SIDEBAR_MODE.CHAT);
  });

  it("answers browse on the first render and the persisted mode once mounted", () => {
    // Given — a tenant that last used the chat; the server rendered browse.
    useAppSidebarMode.setState({ mode: APP_SIDEBAR_MODE.CHAT });
    const renders: string[] = [];

    // When
    renderHook(() => {
      const mode = useHydratedAppSidebarMode();
      renders.push(mode);
      return mode;
    });

    // Then — the hydrating render matches the HTML, the next one the store.
    expect(renders[0]).toBe(APP_SIDEBAR_MODE.BROWSE);
    expect(renders[renders.length - 1]).toBe(APP_SIDEBAR_MODE.CHAT);
  });
});
