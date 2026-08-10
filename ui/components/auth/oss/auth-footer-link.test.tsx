import { render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";

import { AuthFooterLink } from "./auth-footer-link";

const navigationState = vi.hoisted(() => ({
  searchParams: new URLSearchParams(),
}));

vi.mock("next/navigation", () => ({
  useSearchParams: () => navigationState.searchParams,
}));

describe("AuthFooterLink", () => {
  it("should preserve attribution params in the target href", () => {
    // Given
    navigationState.searchParams = new URLSearchParams(
      "promo_code=black-hat-2026&utm_source=blackhat&foo=bar",
    );

    // When
    render(
      <AuthFooterLink
        text="Need to create an account?"
        linkText="Sign up"
        href="/sign-up"
      />,
    );

    // Then
    expect(screen.getByRole("link", { name: "Sign up" })).toHaveAttribute(
      "href",
      "/sign-up?promo_code=black-hat-2026&utm_source=blackhat",
    );
  });
});
