import { render, screen } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";

const navigationMocks = vi.hoisted(() => ({
  notFound: vi.fn(() => {
    throw new Error("NEXT_NOT_FOUND");
  }),
}));

vi.mock("next/navigation", () => ({
  notFound: navigationMocks.notFound,
}));

vi.mock("@/app/(auth)/alerts/_components/alert-public-action", () => ({
  ALERT_PUBLIC_ACTIONS: {
    CONFIRM: "confirm",
    UNSUBSCRIBE: "unsubscribe",
  },
  AlertPublicAction: ({
    action,
    token,
  }: {
    action: string;
    token: string | null;
  }) => (
    <div>
      <span>Public alerts action</span>
      <span>{action}</span>
      <span>{token}</span>
    </div>
  ),
}));

import AlertsConfirmPage from "../confirm/page";
import AlertsUnsubscribePage from "../unsubscribe/page";

const unreadableSearchParams = {
  then: () => {
    throw new Error("search params should not be read");
  },
} as unknown as Promise<{ token?: string }>;

describe("alerts public pages", () => {
  beforeEach(() => {
    delete process.env.NEXT_PUBLIC_IS_CLOUD_ENV;
    navigationMocks.notFound.mockClear();
  });

  it("should not render the confirm page when Cloud is disabled", async () => {
    // Given / When / Then
    await expect(
      AlertsConfirmPage({ searchParams: unreadableSearchParams }),
    ).rejects.toThrow("NEXT_NOT_FOUND");
    expect(navigationMocks.notFound).toHaveBeenCalledOnce();
  });

  it("should not render the unsubscribe page when Cloud is disabled", async () => {
    // Given / When / Then
    await expect(
      AlertsUnsubscribePage({ searchParams: unreadableSearchParams }),
    ).rejects.toThrow("NEXT_NOT_FOUND");
    expect(navigationMocks.notFound).toHaveBeenCalledOnce();
  });

  it("should render the confirm action when Cloud is enabled", async () => {
    // Given
    process.env.NEXT_PUBLIC_IS_CLOUD_ENV = "true";

    // When
    render(
      await AlertsConfirmPage({
        searchParams: Promise.resolve({ token: "confirm-token" }),
      }),
    );

    // Then
    expect(screen.getByText("Public alerts action")).toBeInTheDocument();
    expect(screen.getByText("confirm")).toBeInTheDocument();
    expect(screen.getByText("confirm-token")).toBeInTheDocument();
  });

  it("should render the unsubscribe action when Cloud is enabled", async () => {
    // Given
    process.env.NEXT_PUBLIC_IS_CLOUD_ENV = "true";

    // When
    render(
      await AlertsUnsubscribePage({
        searchParams: Promise.resolve({ token: "unsubscribe-token" }),
      }),
    );

    // Then
    expect(screen.getByText("Public alerts action")).toBeInTheDocument();
    expect(screen.getByText("unsubscribe")).toBeInTheDocument();
    expect(screen.getByText("unsubscribe-token")).toBeInTheDocument();
  });
});
