import { render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";

import { AuthLayout } from "./auth-layout";
import { PublicAuthShell } from "./public-auth-shell";

vi.mock("@/components/ThemeSwitch", () => ({
  ThemeSwitch: ({ "aria-label": ariaLabel }: { "aria-label"?: string }) => (
    <button type="button" aria-label={ariaLabel} />
  ),
}));

describe("AuthLayout", () => {
  it("renders the auth card title and content", () => {
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
  });

  it("renders the brand in the centered auth layout flow above the card", () => {
    // Given
    const title = "Sign in to Prowler";

    // When
    render(
      <AuthLayout title={title}>
        <form aria-label="Sign in form">Form content</form>
      </AuthLayout>,
    );

    // Then
    const brand = screen.getByRole("img", { name: /prowler/i });
    const brandWrapper = brand.parentElement;
    const cardTitle = screen.getByText(title);

    expect(brand).toBeVisible();
    expect(brandWrapper).toHaveClass("relative", "z-10", "mb-8", "w-[200px]");
    expect(brandWrapper).not.toHaveClass("absolute", "top-8");
    expect(brand.compareDocumentPosition(cardTitle)).toBe(
      Node.DOCUMENT_POSITION_FOLLOWING,
    );
  });
});

describe("PublicAuthShell", () => {
  it("does not render a shell-level absolute brand", () => {
    // Given / When
    render(
      <PublicAuthShell>
        <main>Auth page</main>
      </PublicAuthShell>,
    );

    // Then
    expect(
      screen.queryByRole("img", { name: /prowler/i }),
    ).not.toBeInTheDocument();
    expect(screen.getByText("Auth page")).toBeVisible();
  });
});
