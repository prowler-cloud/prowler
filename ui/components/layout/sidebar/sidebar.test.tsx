import { cleanup, render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

import { Sidebar } from "./sidebar";

vi.mock("@/hooks/use-store", () => ({
  useStore: () => ({
    isOpen: true,
    getOpenState: () => true,
    setIsHover: vi.fn(),
    settings: { disabled: false },
  }),
}));

vi.mock("./menu", () => ({
  Menu: () => <nav />,
}));

describe("Sidebar", () => {
  afterEach(() => {
    cleanup();
    vi.unstubAllEnvs();
  });

  it("renders the Local Server lockup outside Cloud", () => {
    // Given
    vi.stubEnv("NEXT_PUBLIC_IS_CLOUD_ENV", "false");

    // When
    render(<Sidebar />);

    // Then
    expect(
      screen.getByRole("img", { name: "Prowler Local Server" }),
    ).toBeVisible();
  });

  it("renders the Prowler Cloud lockup in Cloud", () => {
    // Given
    vi.stubEnv("NEXT_PUBLIC_IS_CLOUD_ENV", "true");

    // When
    render(<Sidebar />);

    // Then
    expect(screen.getByRole("img", { name: "Prowler Cloud" })).toBeVisible();
  });
});
