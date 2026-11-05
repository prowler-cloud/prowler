import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import { ApiKeyLinkCard } from "./api-key-link-card";

describe("ApiKeyLinkCard", () => {
  it("links directly to the API Keys section in the user profile", () => {
    // Given / When
    render(<ApiKeyLinkCard />);

    // Then
    expect(
      screen.getByRole("link", { name: /go to profile/i }),
    ).toHaveAttribute("href", "/profile#api-keys");
  });
});
