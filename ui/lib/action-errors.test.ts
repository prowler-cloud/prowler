import { describe, expect, it } from "vitest";

import {
  ACTION_ERROR_MESSAGES,
  ACTION_ERROR_STATUS,
  getActionErrorMessage,
} from "./action-errors";

describe("getActionErrorMessage", () => {
  it("should use the default permission error for forbidden responses", () => {
    // Given
    const result = {
      error: "You do not have permission to perform this action.",
      status: ACTION_ERROR_STATUS.FORBIDDEN,
    };

    // When
    const message = getActionErrorMessage(result);

    // Then
    expect(message).toBe(ACTION_ERROR_MESSAGES[ACTION_ERROR_STATUS.FORBIDDEN]);
  });

  it("should use the default subscription error for payment-required responses", () => {
    // Given
    const result = {
      error: "Payment required.",
      status: ACTION_ERROR_STATUS.PAYMENT_REQUIRED,
    };

    // When
    const message = getActionErrorMessage(result);

    // Then
    expect(message).toBe(
      ACTION_ERROR_MESSAGES[ACTION_ERROR_STATUS.PAYMENT_REQUIRED],
    );
  });

  it("should use a feature override for handled statuses", () => {
    // Given
    const result = {
      error: "You do not have permission to perform this action.",
      status: ACTION_ERROR_STATUS.FORBIDDEN,
    };
    const override = "You don't have permission to manage alerts.";

    // When
    const message = getActionErrorMessage(result, {
      messages: {
        [ACTION_ERROR_STATUS.FORBIDDEN]: override,
      },
    });

    // Then
    expect(message).toBe(override);
  });

  it("should keep the API error for unhandled statuses", () => {
    // Given
    const result = {
      error: "Apply at least one alert-compatible Findings filter.",
      status: 400,
    };

    // When
    const message = getActionErrorMessage(result);

    // Then
    expect(message).toBe(result.error);
  });
});
