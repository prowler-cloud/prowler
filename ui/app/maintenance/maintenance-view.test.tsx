import { render, screen } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { MaintenanceView } from "./maintenance-view";

describe("MaintenanceView", () => {
  const reloadMock = vi.fn();
  const fetchMock = vi.fn();

  beforeEach(() => {
    vi.stubGlobal("fetch", fetchMock);
    // jsdom's `window.location.reload` is a no-op that throws if called; replace
    // the whole `location` so we can observe reloads without navigation.
    Object.defineProperty(window, "location", {
      configurable: true,
      value: { ...window.location, reload: reloadMock },
    });
  });

  afterEach(() => {
    vi.unstubAllGlobals();
    vi.clearAllMocks();
    vi.useRealTimers();
  });

  it("renders the given message and refresh notice", () => {
    // When
    render(<MaintenanceView message="Scheduled DB maintenance." />);

    // Then
    expect(screen.getByText("Under maintenance")).toBeInTheDocument();
    expect(screen.getByText("Scheduled DB maintenance.")).toBeInTheDocument();
    expect(
      screen.getByText(
        "This page refreshes automatically once maintenance is complete.",
      ),
    ).toBeInTheDocument();
  });

  it("never makes a cross-origin fetch from the browser", () => {
    // When
    render(<MaintenanceView message="Down for maintenance." />);

    // Then
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("reloads the page on an interval so the edge gate can redirect away", () => {
    // Given
    vi.useFakeTimers();

    // When
    render(<MaintenanceView message="Down for maintenance." />);
    expect(reloadMock).not.toHaveBeenCalled();

    vi.advanceTimersByTime(15000); // one interval
    expect(reloadMock).toHaveBeenCalledTimes(1);

    vi.advanceTimersByTime(15000); // second interval
    expect(reloadMock).toHaveBeenCalledTimes(2);
  });

  it("stops reloading after unmount", () => {
    // Given
    vi.useFakeTimers();

    // When
    const { unmount } = render(
      <MaintenanceView message="Down for maintenance." />,
    );
    unmount();
    vi.advanceTimersByTime(15000);

    // Then
    expect(reloadMock).not.toHaveBeenCalled();
  });
});
