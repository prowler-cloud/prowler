import { act, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { SIDE_PANEL_TAB, useSidePanelStore } from "@/store/side-panel";

import { SidePanelTrigger } from "./side-panel-trigger";

const { isCloudMock } = vi.hoisted(() => ({ isCloudMock: vi.fn(() => true) }));

vi.mock("@/lib/shared/env", () => ({ isCloud: isCloudMock }));

vi.mock("next/navigation", () => ({
  usePathname: () => "/findings",
}));

const HINT_DELAY_MS = 1500;

describe("SidePanelTrigger discovery callout", () => {
  beforeEach(() => {
    vi.useFakeTimers();
    isCloudMock.mockReturnValue(true);
    localStorage.clear();
    useSidePanelStore.setState({
      isOpen: false,
      selectedTab: SIDE_PANEL_TAB.AI_CHAT,
      hasBeenOpened: false,
      hasSeenAiTriggerHint: false,
    });
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it("surfaces the callout once, after the settle delay", () => {
    // Given / When
    render(<SidePanelTrigger />);

    // Then: nothing competes with the page while it loads
    expect(screen.queryByTestId("side-panel-ai-hint")).not.toBeInTheDocument();

    // When: the delay elapses
    act(() => vi.advanceTimersByTime(HINT_DELAY_MS));

    // Then
    expect(screen.getByTestId("side-panel-ai-hint")).toBeInTheDocument();
    expect(
      screen.getByText("Ask Lighthouse AI from any page"),
    ).toBeInTheDocument();
  });

  it("never surfaces the callout again once seen", () => {
    // Given: a returning user
    useSidePanelStore.setState({ hasSeenAiTriggerHint: true });

    // When
    render(<SidePanelTrigger />);
    act(() => vi.advanceTimersByTime(HINT_DELAY_MS * 2));

    // Then
    expect(screen.queryByTestId("side-panel-ai-hint")).not.toBeInTheDocument();
  });

  it("dismisses and persists via Got it", () => {
    // Given
    render(<SidePanelTrigger />);
    act(() => vi.advanceTimersByTime(HINT_DELAY_MS));

    // When
    fireEvent.click(screen.getByRole("button", { name: "Got it" }));

    // Then
    expect(screen.queryByTestId("side-panel-ai-hint")).not.toBeInTheDocument();
    expect(useSidePanelStore.getState().hasSeenAiTriggerHint).toBe(true);
    const persisted = JSON.parse(
      localStorage.getItem("side-panel-store") ?? "{}",
    );
    expect(persisted.state.hasSeenAiTriggerHint).toBe(true);
  });

  it("retires the callout when the user opens the chat from the trigger", () => {
    // Given
    render(<SidePanelTrigger />);
    act(() => vi.advanceTimersByTime(HINT_DELAY_MS));

    // When
    fireEvent.click(screen.getByTestId("side-panel-ai-trigger"));

    // Then: the panel opened on the AI tab and the hint is retired for good
    expect(useSidePanelStore.getState().isOpen).toBe(true);
    expect(useSidePanelStore.getState().hasSeenAiTriggerHint).toBe(true);
    expect(screen.queryByTestId("side-panel-ai-hint")).not.toBeInTheDocument();
  });

  it("retires the callout when the chat opens from anywhere else", () => {
    // Given: the callout is showing
    render(<SidePanelTrigger />);
    act(() => vi.advanceTimersByTime(HINT_DELAY_MS));
    expect(screen.getByTestId("side-panel-ai-hint")).toBeInTheDocument();

    // When: another entry point (⌘., Overview banner) opens the AI chat
    act(() => useSidePanelStore.getState().openPanel(SIDE_PANEL_TAB.AI_CHAT));

    // Then
    expect(screen.queryByTestId("side-panel-ai-hint")).not.toBeInTheDocument();
  });

  it("glows while undiscovered and calms once dismissed", () => {
    // Given: first visit; the icon starts calm during page load
    const { container } = render(<SidePanelTrigger />);
    expect(container.querySelector("animate")).not.toBeInTheDocument();

    // When: the callout appears
    act(() => vi.advanceTimersByTime(HINT_DELAY_MS));

    // Then: the animated aura glows alongside it
    expect(container.querySelector("animate")).toBeInTheDocument();

    // When: the user dismisses the hint
    fireEvent.click(screen.getByRole("button", { name: "Got it" }));

    // Then: the icon settles back to its calm rendering
    expect(container.querySelector("animate")).not.toBeInTheDocument();
  });

  it("stays quiet in OSS where the trigger does not render", () => {
    // Given
    isCloudMock.mockReturnValue(false);

    // When
    const { container } = render(<SidePanelTrigger />);
    act(() => vi.advanceTimersByTime(HINT_DELAY_MS));

    // Then
    expect(container).toBeEmptyDOMElement();
    expect(screen.queryByTestId("side-panel-ai-hint")).not.toBeInTheDocument();
  });
});
