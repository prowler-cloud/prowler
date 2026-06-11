import { describe, expect, it } from "vitest";

import {
  getInvitationErrorDisplay,
  INVITATION_ERROR_FLOW,
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
      const result = getInvitationErrorDisplay(
        response,
        INVITATION_ERROR_FLOW.ACCEPT,
      );

      // Then
      expect(result.message).toBe(INVITATION_ERROR_MESSAGES.EXPIRED);
      expect(result.canRetry).toBe(false);
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
      const result = getInvitationErrorDisplay(
        response,
        INVITATION_ERROR_FLOW.ACCEPT,
      );

      // Then
      expect(result.message).toBe(INVITATION_ERROR_MESSAGES.NO_LONGER_VALID);
      expect(result.canRetry).toBe(false);
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
      const result = getInvitationErrorDisplay(
        response,
        INVITATION_ERROR_FLOW.ACCEPT,
      );

      // Then
      expect(result.message).toBe(INVITATION_ERROR_MESSAGES.NOT_VALID);
      expect(result.canRetry).toBe(false);
    });

    it("should not allow retry for client-side malformed tokens", () => {
      // Given
      const response = {
        error: "Invalid invitation token",
      };

      // When
      const result = getInvitationErrorDisplay(
        response,
        INVITATION_ERROR_FLOW.ACCEPT,
      );

      // Then
      expect(result.message).toBe(INVITATION_ERROR_MESSAGES.INVALID_FALLBACK);
      expect(result.canRetry).toBe(false);
    });
  });

  describe("when mapping invitation signup errors", () => {
    it("should not identify generic data errors as invitation token errors", () => {
      // Given
      const error = {
        status: "400",
        code: "invalid",
        detail: "Invalid request data.",
        source: { pointer: "/data" },
      };

      // When
      const result = isInvitationTokenError(error);

      // Then
      expect(result).toBe(false);
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
      const result = getInvitationErrorDisplay(
        response,
        INVITATION_ERROR_FLOW.SIGNUP,
      );

      // Then
      expect(result.message).toBe(INVITATION_ERROR_MESSAGES.INVALID_FALLBACK);
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
      const result = getInvitationErrorDisplay(
        response,
        INVITATION_ERROR_FLOW.SIGNUP,
      );

      // Then
      expect(result.message).toBe(INVITATION_ERROR_MESSAGES.NOT_VALID);
      expect(result.canRetry).toBe(false);
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
      const result = getInvitationErrorDisplay(
        response,
        INVITATION_ERROR_FLOW.ACCEPT,
      );

      // Then
      expect(result.message).toBe(INVITATION_ERROR_MESSAGES.INVALID_FALLBACK);
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
      const result = getInvitationErrorDisplay(
        response,
        INVITATION_ERROR_FLOW.ACCEPT,
      );

      // Then
      expect(result.message).toBe(INVITATION_ERROR_MESSAGES.UNEXPECTED);
      expect(result.canRetry).toBe(true);
    });
  });
});
