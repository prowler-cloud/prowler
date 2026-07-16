import { render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";

import { AuthLayout } from "./auth-layout";

vi.mock("@/components/ThemeSwitch", () => ({
  ThemeSwitch: () => <button type="button">Auth card theme toggle</button>,
}));

describe("AuthLayout", () => {
  it("renders the auth card title and content without the theme toggle", () => {
    // Given
    const title = "Sign in to Prowler";

    // When
    render(
      <AuthLayout title={title}>
        <form aria-label="Sign in form">Form content</form>
      </AuthLayout>,
    );

    // Then
    expect(screen.getByText(title)).toBeVisible();
    expect(screen.getByRole("form", { name: "Sign in form" })).toBeVisible();
    expect(
      screen.queryByRole("button", { name: "Auth card theme toggle" }),
    ).not.toBeInTheDocument();
  });
});
