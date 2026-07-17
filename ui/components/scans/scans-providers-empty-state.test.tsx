import { render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

import { ADD_PROVIDER_HREF } from "@/lib/providers-navigation";

import { ScansProvidersEmptyState } from "./scans-providers-empty-state";

describe("ScansProvidersEmptyState", () => {
  afterEach(() => {
    vi.unstubAllEnvs();
  });

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

  it("mentions imported scans in the disconnected hint only in Cloud", () => {
    vi.stubEnv("NEXT_PUBLIC_IS_CLOUD_ENV", "true");

    render(<ScansProvidersEmptyState thereIsNoProviders={false} />);

    expect(
      screen.getByText(/imported scans still appear below/i),
    ).toBeInTheDocument();
  });

  it("omits the imported-scans copy in the disconnected hint outside Cloud", () => {
    vi.stubEnv("NEXT_PUBLIC_IS_CLOUD_ENV", "false");

    render(<ScansProvidersEmptyState thereIsNoProviders={false} />);

    expect(
      screen.queryByText(/imported scans still appear below/i),
    ).not.toBeInTheDocument();
    // The base guidance still shows so the hint stays actionable.
    expect(
      screen.getByText(/connect one to launch on-demand scans/i),
    ).toBeInTheDocument();
  });

  it("does not render the provider wizard dialog in Scans", () => {
    render(<ScansProvidersEmptyState thereIsNoProviders />);

    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
  });
});
