import { render } from "@testing-library/react";
import { beforeEach, describe, expect, it } from "vitest";

import { useAppSidebarMode } from "./app-sidebar-mode-store";
import { AppSidebarModeSync } from "./app-sidebar-mode-sync";
import { APP_SIDEBAR_MODE } from "./types";

describe("AppSidebarModeSync", () => {
  beforeEach(() => {
    useAppSidebarMode.setState({ mode: APP_SIDEBAR_MODE.CHAT });
  });

  it("restores the requested sidebar mode when a route mounts", () => {
    // Given / When
    render(<AppSidebarModeSync mode={APP_SIDEBAR_MODE.BROWSE} />);

    // Then
    expect(useAppSidebarMode.getState().mode).toBe(APP_SIDEBAR_MODE.BROWSE);
  });
});
