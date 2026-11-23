import { render, screen } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";

import SignUp from "./page";

const { redirectMock, isSelfRegistrationEnabledMock } = vi.hoisted(() => ({
  redirectMock: vi.fn(),
  isSelfRegistrationEnabledMock: vi.fn(),
}));

vi.mock("next/navigation", () => ({
  redirect: redirectMock,
}));

vi.mock("@/lib/shared/env", () => ({
  isCloud: () => false,
  isSelfRegistrationEnabled: isSelfRegistrationEnabledMock,
}));

vi.mock("@/lib/helper", () => ({
  getAuthUrl: () => "",
  isGithubOAuthEnabled: false,
  isGoogleOAuthEnabled: false,
}));

vi.mock("@/components/auth/oss", () => ({
  AuthForm: ({ invitationToken }: { invitationToken?: string | null }) => (
    <div
      data-testid="auth-form"
      data-invitation-token={invitationToken ?? ""}
    />
  ),
}));

const renderPage = (searchParams: Record<string, string> = {}) =>
  SignUp({ searchParams: Promise.resolve(searchParams) });

describe("SignUp page", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    // next/navigation's redirect() never returns; mirror that so the page
    // stops rendering the way it does in Next.
    redirectMock.mockImplementation((url: string) => {
      throw new Error(`NEXT_REDIRECT:${url}`);
    });
  });

  describe("when self-registration is enabled", () => {
    it("should render the sign-up form", async () => {
      // Given
      isSelfRegistrationEnabledMock.mockReturnValue(true);

      // When
      render(await renderPage());

      // Then
      expect(screen.getByTestId("auth-form")).toBeInTheDocument();
      expect(redirectMock).not.toHaveBeenCalled();
    });
  });

  describe("when self-registration is disabled", () => {
    it("should redirect to sign-in without an invitation", async () => {
      // Given
      isSelfRegistrationEnabledMock.mockReturnValue(false);

      // When / Then
      await expect(renderPage()).rejects.toThrow("NEXT_REDIRECT:/sign-in");
    });

    it("should still render the form for an invited user", async () => {
      // Given
      isSelfRegistrationEnabledMock.mockReturnValue(false);

      // When
      render(await renderPage({ invitation_token: "TESTING1234567" }));

      // Then
      expect(screen.getByTestId("auth-form")).toHaveAttribute(
        "data-invitation-token",
        "TESTING1234567",
      );
      expect(redirectMock).not.toHaveBeenCalled();
    });
  });
});
