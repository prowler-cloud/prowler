import { fireEvent, render, screen } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { SIDE_PANEL_TAB, useSidePanelStore } from "@/store/side-panel";

import { SidePanelTrigger } from "./side-panel-trigger";

const { isCloudMock } = vi.hoisted(() => ({ isCloudMock: vi.fn(() => true) }));

vi.mock("@/lib/shared/env", () => ({ isCloud: isCloudMock }));

vi.mock("next/navigation", () => ({
  usePathname: () => "/findings",
}));

describe("SidePanelTrigger", () => {
  beforeEach(() => {
    isCloudMock.mockReturnValue(true);
    localStorage.clear();
    useSidePanelStore.setState({
      isOpen: false,
      selectedTab: SIDE_PANEL_TAB.CONTEXT,
      hasBeenOpened: false,
    });
  });

  it("opens the side panel on the AI chat", () => {
    // Given
    render(<SidePanelTrigger />);

    // When
    fireEvent.click(screen.getByRole("button", { name: "Ask Lighthouse AI" }));

    // Then
    expect(useSidePanelStore.getState().isOpen).toBe(true);
    expect(useSidePanelStore.getState().selectedTab).toBe(
      SIDE_PANEL_TAB.AI_CHAT,
    );
  });

  it("renders nothing in OSS", () => {
    // Given
    isCloudMock.mockReturnValue(false);

    // When
    const { container } = render(<SidePanelTrigger />);

    // Then
    expect(container).toBeEmptyDOMElement();
  });
});
