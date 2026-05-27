import { describe, expect, it } from "vitest";

import {
  getInvitationErrorDisplay,
  INVITATION_ERROR_MESSAGES,
  isInvitationTokenError,
} from "./invitation-errors";

describe("getInvitationErrorDisplay", () => {
  describe("when mapping invitation accept errors", () => {
    it("should show expired message for token_expired responses", () => {
      // Given
      const response = {
        status: 410,
        errors: [
          {
            status: "410",
            code: "token_expired",
            detail: "The invitation token has expired and is no longer valid.",
          },
        ],
      };

      // When
      const result = getInvitationErrorDisplay(response, "accept");

      // Then
      expect(result.message).toBe(INVITATION_ERROR_MESSAGES.expired);
      expect(result.canRetry).toBe(false);
      expect(result.needsSignOut).toBe(false);
    });

    it("should show no-longer-valid message for already accepted or revoked invitations", () => {
      // Given
      const response = {
        status: 400,
        errors: [
          {
            status: "400",
            code: "invalid",
            detail: "This invitation is no longer valid.",
          },
        ],
      };

      // When
      const result = getInvitationErrorDisplay(response, "accept");

      // Then
      expect(result.message).toBe(INVITATION_ERROR_MESSAGES.noLongerValid);
      expect(result.canRetry).toBe(false);
      expect(result.needsSignOut).toBe(false);
    });

    it("should show not-valid message for missing invitation tokens", () => {
      // Given
      const response = {
        status: 404,
        errors: [
          {
            status: "404",
            code: "not_found",
            detail: "Invitation is not valid.",
          },
        ],
      };

      // When
      const result = getInvitationErrorDisplay(response, "accept");

      // Then
      expect(result.message).toBe(INVITATION_ERROR_MESSAGES.notValid);
      expect(result.canRetry).toBe(false);
      expect(result.needsSignOut).toBe(false);
    });
  });

  describe("when mapping invitation signup errors", () => {
    it("should identify invitation token data errors", () => {
      // Given
      const error = {
        status: "400",
        code: "invalid",
        detail: "Invalid invitation code.",
        source: { pointer: "/data" },
      };

      // When
      const result = isInvitationTokenError(error);

      // Then
      expect(result).toBe(true);
    });

    it("should identify invitation token field errors", () => {
      // Given
      const error = {
        status: "400",
        code: "invalid",
        detail: "Invalid invitation code.",
        source: { pointer: "/data/attributes/invitation_token" },
      };

      // When
      const result = isInvitationTokenError(error);

      // Then
      expect(result).toBe(true);
    });

    it("should use generic invalid fallback for non-invitation signup errors", () => {
      // Given
      const response = {
        status: 400,
        errors: [
          {
            status: "400",
            code: "invalid",
            detail: "Invalid email address.",
            source: { pointer: "/data/attributes/email" },
          },
        ],
      };

      // When
      const result = getInvitationErrorDisplay(response, "signup");

      // Then
      expect(result.message).toBe(INVITATION_ERROR_MESSAGES.invalidFallback);
      expect(result.canRetry).toBe(false);
    });

    it("should show not-valid message for signup invalid invitation tokens", () => {
      // Given
      const response = {
        status: 400,
        errors: [
          {
            status: "400",
            code: "invalid",
            detail: "Invalid invitation code.",
            source: { pointer: "/data/attributes/invitation_token" },
          },
        ],
      };

      // When
      const result = getInvitationErrorDisplay(response, "signup");

      // Then
      expect(result.message).toBe(INVITATION_ERROR_MESSAGES.notValid);
      expect(result.canRetry).toBe(false);
      expect(result.needsSignOut).toBe(false);
    });
  });

  describe("when the response is unexpected", () => {
    it("should use generic invalid fallback for unmapped invalid responses", () => {
      // Given
      const response = {
        status: 400,
        errors: [
          {
            status: "400",
            code: "invalid",
            detail: "Unexpected invalid invitation response.",
          },
        ],
      };

      // When
      const result = getInvitationErrorDisplay(response, "accept");

      // Then
      expect(result.message).toBe(INVITATION_ERROR_MESSAGES.invalidFallback);
      expect(result.canRetry).toBe(false);
    });

    it("should allow retry for unknown responses", () => {
      // Given
      const response = {
        status: 500,
        errors: [
          {
            status: "500",
            code: "server_error",
            detail: "Something exploded.",
          },
        ],
      };

      // When
      const result = getInvitationErrorDisplay(response, "accept");

      // Then
      expect(result.message).toBe(INVITATION_ERROR_MESSAGES.unexpected);
      expect(result.canRetry).toBe(true);
    });
  });
});
