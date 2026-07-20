import { fireEvent, render, screen } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { ThemeSwitch } from "./ThemeSwitch";

const { setThemeMock, themeState } = vi.hoisted(() => ({
  setThemeMock: vi.fn(),
  themeState: { current: "light" },
}));

vi.mock("next-themes", () => ({
  useTheme: () => ({ theme: themeState.current, setTheme: setThemeMock }),
}));

describe("ThemeSwitch", () => {
  beforeEach(() => {
    setThemeMock.mockClear();
    themeState.current = "light";
  });

  it("exposes an accessible switch reflecting the current mode", () => {
    // Given / When
    render(<ThemeSwitch />);

    // Then
    const control = screen.getByRole("switch", {
      name: "Switch to dark mode",
    });
    expect(control).toHaveAttribute("aria-checked", "true");
  });

  it("toggles to the opposite theme on click", () => {
    // Given
    render(<ThemeSwitch />);

    // When
    fireEvent.click(screen.getByRole("switch"));

    // Then
    expect(setThemeMock).toHaveBeenCalledWith("dark");
  });

  it("renders as a shared ghost icon button, matching the navbar cluster", () => {
    // Given / When
    render(<ThemeSwitch />);

    // Then: same 32px square treatment as the other navbar actions
    const control = screen.getByRole("switch");
    expect(control).toHaveClass("size-8");
    expect(control).not.toHaveClass("rounded-full");
  });
});
