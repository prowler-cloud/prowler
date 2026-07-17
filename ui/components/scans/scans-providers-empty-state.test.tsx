import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import { ADD_PROVIDER_HREF } from "@/lib/providers-navigation";

import { ScansProvidersEmptyState } from "./scans-providers-empty-state";

describe("ScansProvidersEmptyState", () => {
  it("shows the add-provider hint with a providers page CTA when there are no providers", () => {
    render(<ScansProvidersEmptyState thereIsNoProviders />);

    expect(screen.getByText("No Providers Configured")).toBeInTheDocument();
    const cta = screen.getByRole("link", { name: /add a provider/i });
    expect(cta).toHaveAttribute("href", ADD_PROVIDER_HREF);
    expect(cta.tagName).toBe("A");
  });

  it("shows the no-connected-providers hint with a providers page CTA", () => {
    render(<ScansProvidersEmptyState thereIsNoProviders={false} />);

    expect(screen.getByText("No Connected Providers")).toBeInTheDocument();
    const cta = screen.getByRole("link", { name: /review providers/i });
    expect(cta).toHaveAttribute("href", "/providers");
    expect(cta.tagName).toBe("A");
  });

  it("does not render the provider wizard dialog in Scans", () => {
    render(<ScansProvidersEmptyState thereIsNoProviders />);

    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
  });
});
