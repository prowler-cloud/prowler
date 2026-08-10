import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it } from "vitest";

import { UsageLimitBanner } from "./usage-limit-banner";

describe("UsageLimitBanner", () => {
  beforeEach(() => {
    window.sessionStorage.clear();
  });

  it("preserves the existing Cloud usage-limit presentation", async () => {
    // Given / When
    render(<UsageLimitBanner />);

    // Then
    const alert = await screen.findByRole("alert");
    expect(alert).toHaveClass(
      "animate-fade-in",
      "border-orange-500",
      "bg-orange-50",
    );
    expect(alert.querySelector("svg")).toHaveClass("lucide-triangle-alert");
    expect(screen.getByText("Usage limit exceeded")).toBeVisible();
    expect(
      screen.getByText(
        "You have exceeded the usage limit of one provider. You can add more providers and run unlimited scans by adding a subscription.",
      ),
    ).toBeVisible();
    expect(
      screen.getByRole("link", { name: "Manage Billing" }),
    ).toHaveAttribute("href", "/billing");
  });

  it("preserves the existing session dismissal behavior", async () => {
    // Given
    const user = userEvent.setup();
    render(<UsageLimitBanner allowHide />);

    // When
    await user.click(await screen.findByRole("button", { name: "Close" }));

    // Then
    expect(screen.queryByRole("alert")).not.toBeInTheDocument();
    expect(window.sessionStorage.getItem("usage-limit-banner-dismissed")).toBe(
      "true",
    );
  });
});
