import { render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";

import { ADD_PROVIDER_HREF } from "@/lib/providers-navigation";

import { ScansProvidersEmptyState } from "./scans-providers-empty-state";

vi.mock("./no-providers-connected", () => ({
  NoProvidersConnected: () => <div>No Connected Providers</div>,
}));

describe("ScansProvidersEmptyState", () => {
  it("shows the add provider message with a providers page CTA", () => {
    // Given/When
    render(<ScansProvidersEmptyState thereIsNoProviders />);

    // Then
    expect(screen.getByText("No Providers Configured")).toBeInTheDocument();
    const cta = screen.getByRole("link", {
      name: /open add provider modal/i,
    });

    expect(cta).toHaveAttribute("href", ADD_PROVIDER_HREF);
    expect(cta.tagName).toBe("A");
  });

  it("does not render the provider wizard in Scans", () => {
    // Given/When
    render(<ScansProvidersEmptyState thereIsNoProviders />);

    // Then
    expect(screen.getByText("No Providers Configured")).toBeInTheDocument();
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
  });

  it("shows the no connected providers message", () => {
    // Given/When
    render(<ScansProvidersEmptyState thereIsNoProviders={false} />);

    // Then
    expect(screen.getByText("No Connected Providers")).toBeInTheDocument();
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
  });
});
