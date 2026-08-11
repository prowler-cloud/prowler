import { fireEvent, render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";

import {
  TRIAL_SIDEBAR_BANNER_VARIANT,
  TrialSidebarBanner,
} from "./trial-sidebar-banner";

describe("TrialSidebarBanner", () => {
  it("preserves the active day-based trial card", () => {
    // Given / When
    render(
      <TrialSidebarBanner
        variant={TRIAL_SIDEBAR_BANNER_VARIANT.ACTIVE_DAYS}
        remaining={7}
      />,
    );

    // Then
    const banner = screen.getByRole("status", { name: "Active trial" });
    expect(banner).toHaveTextContent("Unlimited trial");
    expect(banner).toHaveTextContent("7 days left");
    expect(banner).toHaveTextContent(
      "Unlimited accounts, scans, and daily schedules",
    );
    expect(banner).toHaveTextContent("Explore plans");
    expect(banner).toHaveAttribute("data-slot", "sidebar-trial");
    expect(
      screen.getByRole("link", {
        name: "Explore plans for your unlimited trial",
      }),
    ).toHaveAttribute("href", "/billing");
  });

  it("preserves an active unlimited trial without a counter", () => {
    // Given / When
    render(
      <TrialSidebarBanner
        variant={TRIAL_SIDEBAR_BANNER_VARIANT.ACTIVE_UNLIMITED}
      />,
    );

    // Then
    const banner = screen.getByRole("status", { name: "Active trial" });
    expect(banner).toHaveTextContent("Unlimited trial");
    expect(banner).toHaveTextContent("Trial active");
    expect(banner).toHaveTextContent(
      "Unlimited accounts, scans, and daily schedules",
    );
    expect(banner).toHaveAttribute("data-urgency", "healthy");
    expect(
      screen.getByRole("link", {
        name: "Explore plans for your unlimited trial",
      }),
    ).toHaveAttribute("href", "/billing");
  });

  it("formats a singular remaining day", () => {
    // Given / When
    render(
      <TrialSidebarBanner
        variant={TRIAL_SIDEBAR_BANNER_VARIANT.ACTIVE_DAYS}
        remaining={1}
      />,
    );

    // Then
    const banner = screen.getByRole("status", { name: "Active trial" });
    expect(banner).toHaveTextContent("1 day left");
    expect(banner).toHaveAttribute("data-urgency", "critical");
  });

  it.each([
    { remaining: 1, copy: "1 scan left", urgency: "healthy" },
    { remaining: 5, copy: "5 scans left", urgency: "healthy" },
  ])(
    "formats $remaining remaining scan(s) in the active card",
    ({ remaining, copy, urgency }) => {
      // Given / When
      render(
        <TrialSidebarBanner
          variant={TRIAL_SIDEBAR_BANNER_VARIANT.ACTIVE_SCANS}
          remaining={remaining}
        />,
      );

      // Then
      const banner = screen.getByRole("status", { name: "Active trial" });
      expect(banner).toHaveTextContent(copy);
      expect(banner).toHaveTextContent("Free trial");
      expect(banner).not.toHaveTextContent("Unlimited trial");
      expect(banner).toHaveTextContent(
        "Choose a plan to keep running scans after your trial ends.",
      );
      expect(banner).toHaveAttribute("data-urgency", urgency);
      expect(
        screen.getByRole("link", {
          name: "Explore plans for your free trial",
        }),
      ).toHaveAttribute("href", "/billing");
    },
  );

  it.each([
    { remaining: 0, copy: "0 scans left" },
    { remaining: -4, copy: "0 scans left" },
  ])(
    "marks a scan trial with $remaining remaining as spent",
    ({ remaining, copy }) => {
      // Given / When
      render(
        <TrialSidebarBanner
          variant={TRIAL_SIDEBAR_BANNER_VARIANT.ACTIVE_SCANS}
          remaining={remaining}
        />,
      );

      // Then
      const banner = screen.getByRole("status", { name: "Active trial" });
      expect(banner).toHaveTextContent(copy);
      expect(banner).toHaveAttribute("data-urgency", "critical");
      expect(screen.getByText("Free trial")).toHaveClass(
        "bg-bg-fail-secondary",
      );
    },
  );

  it("renders exhausted scan trials with the existing expired presentation", () => {
    // Given / When
    render(
      <TrialSidebarBanner variant={TRIAL_SIDEBAR_BANNER_VARIANT.EXPIRED} />,
    );

    // Then
    const banner = screen.getByRole("status", { name: "Expired trial" });
    expect(banner).toHaveTextContent("Trial expired");
    expect(banner).toHaveTextContent("Subscription required");
    expect(banner).toHaveTextContent(
      "Subscribe to continue scanning and running scheduled scans.",
    );
    expect(banner).not.toHaveTextContent("0 scans left");
    expect(banner).toHaveAttribute("data-urgency", "critical");
    expect(
      screen.getByRole("link", {
        name: "Explore plans after your trial expired",
      }),
    ).toHaveAttribute("href", "/billing");
  });

  it("invokes the sidebar selection callback from the billing CTA", async () => {
    // Given
    const user = userEvent.setup();
    const onSelect = vi.fn();
    render(
      <TrialSidebarBanner
        variant={TRIAL_SIDEBAR_BANNER_VARIANT.ACTIVE_DAYS}
        remaining={7}
        onSelect={onSelect}
      />,
    );
    document.addEventListener("click", (event) => event.preventDefault(), {
      once: true,
    });

    // When
    await user.click(
      screen.getByRole("link", {
        name: "Explore plans for your unlimited trial",
      }),
    );

    // Then
    expect(onSelect).toHaveBeenCalledOnce();
  });

  // The tilt runs on animation frames and `useReducedMotion` caches its media
  // query module-globally, so both belong in Browser Mode, not jsdom.
  it("renders the decorative glow layer", () => {
    // Given / When
    const { container } = render(
      <TrialSidebarBanner
        variant={TRIAL_SIDEBAR_BANNER_VARIANT.ACTIVE_DAYS}
        remaining={7}
      />,
    );

    // Then
    const glow = container.querySelector('[data-slot="trial-glow"]');
    expect(glow).toBeInTheDocument();
    expect(glow).toHaveClass("motion-reduce:hidden");
  });

  it.each([{ pointerType: "touch" }, { pointerType: "mouse" }])(
    "keeps the card usable under $pointerType input",
    ({ pointerType }) => {
      // Given
      render(
        <TrialSidebarBanner
          variant={TRIAL_SIDEBAR_BANNER_VARIANT.ACTIVE_DAYS}
          remaining={7}
        />,
      );
      const card = screen.getByRole("link", {
        name: "Explore plans for your unlimited trial",
      });

      // When
      fireEvent.pointerMove(card, { clientX: 250, clientY: 60, pointerType });
      fireEvent.pointerLeave(card);

      // Then
      expect(card).toBeInTheDocument();
      expect(card).toHaveTextContent("7 days left");
    },
  );
});
