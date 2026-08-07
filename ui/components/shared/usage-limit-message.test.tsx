import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import { USAGE_LIMIT_MESSAGE } from "@/lib/action-errors";
import { BILLING_URL } from "@/lib/external-urls";

import { UsageLimitMessage } from "./usage-limit-message";

describe("UsageLimitMessage", () => {
  it("renders the shared usage-limit copy", () => {
    render(<UsageLimitMessage />);

    expect(screen.getByText(/exceeded the usage limit/i)).toBeInTheDocument();
  });

  it("links to Prowler Cloud billing", () => {
    render(<UsageLimitMessage />);

    const link = screen.getByRole("link", { name: /manage billing/i });
    expect(link).toHaveAttribute("href", BILLING_URL);
    expect(link).toHaveAttribute("target", "_blank");
    expect(link).toHaveAttribute("rel", "noopener noreferrer");
  });

  it("keeps the copy in sync with the 402 action-error message", () => {
    render(<UsageLimitMessage />);

    expect(screen.getByText(USAGE_LIMIT_MESSAGE)).toBeInTheDocument();
  });

  it("merges a custom className with the base styles", () => {
    const { container } = render(<UsageLimitMessage className="mt-4" />);

    expect(container.firstChild).toHaveClass("mt-4");
    expect(container.firstChild).toHaveClass("text-text-error-primary");
  });
});
