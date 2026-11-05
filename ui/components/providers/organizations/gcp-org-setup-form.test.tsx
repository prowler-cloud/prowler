import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";

import { ORG_SETUP_PHASE } from "@/types/organizations";

import { GcpOrgSetupForm } from "./gcp-org-setup-form";

vi.mock("@/actions/organizations/organizations", () => ({
  updateOrganizationName: vi.fn(),
}));

vi.mock("./hooks/use-org-setup-submission", () => ({
  useOrgSetupSubmission: () => ({
    apiError: null,
    setApiError: vi.fn(),
    submitOrganizationSetup: vi.fn(),
    replaceSecretWarning: null,
    confirmSecretReplace: vi.fn(),
    cancelSecretReplace: vi.fn(),
    discoveryTimedOut: false,
    discoveryFailed: false,
    isSubmissionPending: false,
    keepWaitingForDiscovery: vi.fn(),
    retryDiscovery: vi.fn(),
  }),
}));

describe("GcpOrgSetupForm", () => {
  describe("when static credentials are selected", () => {
    it("should preserve the labels of masked credential fields", async () => {
      // Given
      const user = userEvent.setup();
      render(
        <GcpOrgSetupForm
          onBack={vi.fn()}
          onNext={vi.fn()}
          onFooterChange={vi.fn()}
          onPhaseChange={vi.fn()}
          initialPhase={ORG_SETUP_PHASE.ACCESS}
        />,
      );

      // When
      await user.click(
        screen.getByRole("radio", {
          name: /client id, client secret and refresh token/i,
        }),
      );

      // Then
      expect(screen.getByLabelText("Client Secret")).toHaveAttribute(
        "type",
        "password",
      );
      expect(screen.getByLabelText("Refresh Token")).toHaveAttribute(
        "type",
        "password",
      );
    });
  });
});
