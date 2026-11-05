import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import { USAGE_LIMIT_MESSAGE } from "@/lib/action-errors";
import { PRICING_URL } from "@/lib/external-urls";

import { UsageLimitMessage } from "./usage-limit-message";

describe("UsageLimitMessage", () => {
  it("explains the limit and opens the plans in a new tab", () => {
    // When
    render(<UsageLimitMessage />);

    // Then
    expect(
      screen.getByText(USAGE_LIMIT_MESSAGE, { exact: false }),
    ).toBeVisible();
    const link = screen.getByRole("link", { name: "View plans" });
    expect(link).toHaveAttribute("href", PRICING_URL);
    expect(link).toHaveAttribute("target", "_blank");
    expect(link).toHaveAttribute("rel", "noopener noreferrer");
  });
});
