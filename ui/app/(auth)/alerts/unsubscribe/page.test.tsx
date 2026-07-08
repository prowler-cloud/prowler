import { render, screen } from "@testing-library/react";
import { ReactNode } from "react";
import { describe, expect, it, vi } from "vitest";

import AlertsUnsubscribePage from "./page";

const unsubscribeAlertRecipientMock = vi.hoisted(() => vi.fn());

vi.mock("./unsubscribe-alert-recipient", () => ({
  unsubscribeAlertRecipient: unsubscribeAlertRecipientMock,
}));

vi.mock("@/components/auth/oss/auth-layout", () => ({
  AuthLayout: ({ title, children }: { title: string; children: ReactNode }) => (
    <section aria-label={title}>{children}</section>
  ),
}));

vi.mock("@/components/shadcn", async (importOriginal) => ({
  ...(await importOriginal<Record<string, unknown>>()),
  Button: ({ children }: { children: ReactNode }) => <div>{children}</div>,
}));

vi.mock("next/link", () => ({
  default: ({ children, href }: { children: ReactNode; href: string }) => (
    <a href={href}>{children}</a>
  ),
}));

describe("AlertsUnsubscribePage", () => {
  it("shows a neutral link back to the app after unsubscribing", async () => {
    // Given
    unsubscribeAlertRecipientMock.mockResolvedValueOnce({
      ok: true,
      state: "unsubscribed",
      message:
        "You have been unsubscribed. You will not receive further alerts at this address.",
    });

    // When
    render(
      await AlertsUnsubscribePage({
        searchParams: Promise.resolve({ token: "token-1" }),
      }),
    );

    // Then
    expect(unsubscribeAlertRecipientMock).toHaveBeenCalledWith("token-1");
    expect(screen.getByLabelText("Unsubscribed")).toBeInTheDocument();
    expect(
      screen.getByText(
        "You have been unsubscribed. You will not receive further alerts at this address.",
      ),
    ).toBeVisible();
    expect(
      screen.getByRole("link", { name: "Continue to Prowler" }),
    ).toHaveAttribute("href", "/");
  });
});
