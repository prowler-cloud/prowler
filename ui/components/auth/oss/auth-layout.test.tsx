import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import { AuthLayout } from "./auth-layout";

describe("AuthLayout", () => {
  it("renders the Cloudy brand above the form title, which is the page h1", () => {
    render(
      <AuthLayout title="Sign in">
        <p>form content</p>
      </AuthLayout>,
    );

    const brand = screen.getByRole("img", { name: "Cloudy" });
    const title = screen.getByRole("heading", { level: 1, name: "Sign in" });

    expect(
      brand.compareDocumentPosition(title) & Node.DOCUMENT_POSITION_FOLLOWING,
    ).toBeTruthy();
  });

  it("renders the footer outside the form card, below it", () => {
    render(
      <AuthLayout title="Sign in" footer={<p>footer link</p>}>
        <p>form content</p>
      </AuthLayout>,
    );

    const content = screen.getByText("form content");
    const footer = screen.getByText("footer link");
    const card = content.parentElement!;

    expect(card.contains(footer)).toBe(false);
    expect(
      content.compareDocumentPosition(footer) &
        Node.DOCUMENT_POSITION_FOLLOWING,
    ).toBeTruthy();
  });
});
