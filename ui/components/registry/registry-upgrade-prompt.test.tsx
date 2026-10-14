import { render, screen } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { RegistrySetupPrompt } from "./registry-upgrade-prompt";

const { permissions } = vi.hoisted(() => ({
  permissions: { manage_registry: false },
}));

vi.mock("@/hooks/use-auth", () => ({
  useAuth: () => ({ permissions }),
}));

describe("RegistrySetupPrompt", () => {
  beforeEach(() => {
    permissions.manage_registry = false;
  });

  it("sends Registry managers to connect their key", () => {
    // Given
    permissions.manage_registry = true;

    // When
    render(<RegistrySetupPrompt />);

    // Then
    expect(
      screen.getByRole("link", { name: "Connect Registry" }),
    ).toHaveAttribute("href", "/registry");
  });

  it("asks everyone else for an administrator", () => {
    // When
    render(<RegistrySetupPrompt />);

    // Then
    expect(
      screen.getByText(
        "Ask an administrator to connect Registry before adding custom providers.",
      ),
    ).toBeVisible();
    expect(
      screen.queryByRole("link", { name: "Connect Registry" }),
    ).not.toBeInTheDocument();
  });
});
