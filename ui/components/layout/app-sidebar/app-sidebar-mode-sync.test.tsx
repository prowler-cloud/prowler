import { render } from "@testing-library/react";
import { beforeEach, describe, expect, it } from "vitest";

import { useSidePanelStore } from "@/store/side-panel";

import { useAppSidebarMode } from "./app-sidebar-mode-store";
import { AppSidebarModeSync } from "./app-sidebar-mode-sync";
import { APP_SIDEBAR_MODE } from "./types";

describe("AppSidebarModeSync", () => {
  beforeEach(() => {
    useAppSidebarMode.setState({ mode: APP_SIDEBAR_MODE.CHAT });
    useSidePanelStore.setState({ isOpen: false });
  });

  it("restores the requested sidebar mode when a route mounts", () => {
    // Given / When
    render(<AppSidebarModeSync mode={APP_SIDEBAR_MODE.BROWSE} />);

    // Then
    expect(useAppSidebarMode.getState().mode).toBe(APP_SIDEBAR_MODE.BROWSE);
  });

  it("keeps the side panel open by default", () => {
    // Given
    useSidePanelStore.setState({ isOpen: true });

    // When
    render(<AppSidebarModeSync mode={APP_SIDEBAR_MODE.BROWSE} />);

    // Then
    expect(useSidePanelStore.getState().isOpen).toBe(true);
  });

  it("closes the side panel when the full-page chat mounts", () => {
    // Given
    useSidePanelStore.setState({ isOpen: true });

    // When
    render(<AppSidebarModeSync mode={APP_SIDEBAR_MODE.CHAT} closeSidePanel />);

    // Then
    expect(useSidePanelStore.getState().isOpen).toBe(false);
  });
});
