import { render, screen } from "@testing-library/react";
import { ReactNode } from "react";
import { describe, expect, it, vi } from "vitest";

import AlertsConfirmPage from "./page";

const confirmAlertRecipientMock = vi.hoisted(() => vi.fn());

vi.mock("./confirm-alert-recipient", () => ({
  confirmAlertRecipient: confirmAlertRecipientMock,
}));

vi.mock("@/components/auth/oss/auth-layout", () => ({
  AuthLayout: ({ title, children }: { title: string; children: ReactNode }) => (
    <section aria-label={title}>{children}</section>
  ),
}));

vi.mock("@/components/shadcn", () => ({
  Button: ({ children }: { children: ReactNode }) => <div>{children}</div>,
}));

vi.mock("next/link", () => ({
  default: ({ children, href }: { children: ReactNode; href: string }) => (
    <a href={href}>{children}</a>
  ),
}));

describe("AlertsConfirmPage", () => {
  it("shows the API message after confirming the alert recipient", async () => {
    // Given
    confirmAlertRecipientMock.mockResolvedValueOnce({
      ok: true,
      state: "confirmed",
      message:
        "Your subscription has been confirmed. You will receive alert digests at this address.",
    });

    // When
    render(
      await AlertsConfirmPage({
        searchParams: Promise.resolve({ token: "token-1" }),
      }),
    );

    // Then
    expect(confirmAlertRecipientMock).toHaveBeenCalledWith("token-1");
    expect(screen.getByLabelText("Subscription confirmed")).toBeInTheDocument();
    expect(
      screen.getByText(
        "Your subscription has been confirmed. You will receive alert digests at this address.",
      ),
    ).toBeVisible();
    expect(
      screen.getByRole("link", { name: "Continue to Prowler" }),
    ).toHaveAttribute("href", "/");
  });

  it("shows the subscription link title when confirmation fails", async () => {
    // Given
    confirmAlertRecipientMock.mockResolvedValueOnce({
      ok: false,
      state: "invalid_token",
      message: "This link is invalid or has expired.",
    });

    // When
    render(
      await AlertsConfirmPage({
        searchParams: Promise.resolve({ token: ["expired-token"] }),
      }),
    );

    // Then
    expect(confirmAlertRecipientMock).toHaveBeenCalledWith("expired-token");
    expect(screen.getByLabelText("Subscription link")).toBeInTheDocument();
    expect(
      screen.getByText("This link is invalid or has expired."),
    ).toBeVisible();
  });
});
