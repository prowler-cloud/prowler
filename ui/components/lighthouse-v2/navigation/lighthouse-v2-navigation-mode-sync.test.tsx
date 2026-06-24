import { render, waitFor } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";

import { SIDEBAR_NAVIGATION_MODE } from "@/hooks/use-sidebar";

import { LighthouseV2NavigationModeSync } from "./lighthouse-v2-navigation-mode-sync";

const setNavigationModeMock = vi.fn();

vi.mock("@/hooks/use-sidebar", () => ({
  SIDEBAR_NAVIGATION_MODE: {
    BROWSE: "browse",
    CHAT: "chat",
  },
  useSidebar: (
    selector: (state: {
      setNavigationMode: typeof setNavigationModeMock;
    }) => unknown,
  ) => selector({ setNavigationMode: setNavigationModeMock }),
}));

describe("LighthouseV2NavigationModeSync", () => {
  it("sets the sidebar navigation mode to chat on mount", async () => {
    // Given / When
    render(<LighthouseV2NavigationModeSync />);

    // Then
    await waitFor(() =>
      expect(setNavigationModeMock).toHaveBeenCalledWith(
        SIDEBAR_NAVIGATION_MODE.CHAT,
      ),
    );
  });
});
