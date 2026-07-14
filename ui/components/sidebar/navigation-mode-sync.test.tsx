import { render } from "@testing-library/react";
import { beforeEach, describe, expect, it } from "vitest";

import { SIDEBAR_NAVIGATION_MODE, useSidebar } from "@/hooks/use-sidebar";
import { useSidePanelStore } from "@/store/side-panel";

import { SidebarNavigationModeSync } from "./navigation-mode-sync";

describe("SidebarNavigationModeSync", () => {
  beforeEach(() => {
    useSidebar.setState({
      navigationMode: SIDEBAR_NAVIGATION_MODE.CHAT,
    });
    useSidePanelStore.setState({ isOpen: false });
  });

  it("restores app navigation mode when the overview mounts", () => {
    // Given / When
    render(<SidebarNavigationModeSync mode={SIDEBAR_NAVIGATION_MODE.BROWSE} />);

    // Then
    expect(useSidebar.getState().navigationMode).toBe(
      SIDEBAR_NAVIGATION_MODE.BROWSE,
    );
  });

  it("closes the side panel when the full-page chat mounts", () => {
    // Given
    useSidePanelStore.setState({ isOpen: true });

    // When
    render(
      <SidebarNavigationModeSync
        mode={SIDEBAR_NAVIGATION_MODE.CHAT}
        closeSidePanel
      />,
    );

    // Then
    expect(useSidePanelStore.getState().isOpen).toBe(false);
  });
});
