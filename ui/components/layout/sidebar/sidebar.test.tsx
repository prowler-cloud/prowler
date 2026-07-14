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

  it("labels the expanded open-source product as Local Server", () => {
    // Given
    vi.stubEnv("NEXT_PUBLIC_IS_CLOUD_ENV", "false");

    // When
    render(<Sidebar />);

    // Then
    expect(screen.getByText("Local Server")).toBeVisible();
  });

  it("does not render the Local Server label in Prowler Cloud", () => {
    // Given
    vi.stubEnv("NEXT_PUBLIC_IS_CLOUD_ENV", "true");

    // When
    render(<Sidebar />);

    // Then
    expect(screen.queryByText("Local Server")).not.toBeInTheDocument();
  });
});
