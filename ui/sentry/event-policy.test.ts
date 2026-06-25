import { describe, expect, it } from "vitest";

import type {
  SentryEventHint,
  SentryEventPolicyOptions,
  SentryPolicyEvent,
} from "./event-policy";
import {
  applySentryEventPolicy,
  isErrorAlreadyReported,
  markErrorAsReported,
} from "./event-policy";

describe("applySentryEventPolicy", () => {
  describe("when events are actionable", () => {
    it("should keep error events", () => {
      // Given
      const event = {
        level: "error",
        message: "Unexpected failure",
      } satisfies SentryPolicyEvent & { level: string; message: string };
      const options: SentryEventPolicyOptions = { source: "client" };

      // When
      const result = applySentryEventPolicy(event, undefined, options);

      // Then
      expect(result).toBe(event);
      expect(result).toMatchObject({
        tags: {
          actionability: "actionable",
          kind: "runtime",
          source: "client",
        },
      });
    });

    it("should keep fatal events", () => {
      // Given
      const event = { level: "fatal", message: "Runtime crashed" };

      // When
      const result = applySentryEventPolicy(event);

      // Then
      expect(result).toBe(event);
    });

    it("should keep events without a level", () => {
      // Given
      const event = { message: "Default Sentry event" };

      // When
      const result = applySentryEventPolicy(event);

      // Then
      expect(result).toBe(event);
    });

    it("should keep fatal runtime messages that contain an expected HTTP status number", () => {
      // Given
      const event = {
        level: "fatal",
        message: "Runtime worker 401 crashed unexpectedly",
      };

      // When
      const result = applySentryEventPolicy(event);

      // Then
      expect(result).toBe(event);
      expect(result).toMatchObject({
        tags: {
          actionability: "actionable",
          kind: "runtime",
        },
      });
    });

    it("should keep runtime error messages that contain an expected HTTP status number", () => {
      // Given
      const event = {
        level: "error",
        message: "Background import 404 failed after a null dereference",
      };

      // When
      const result = applySentryEventPolicy(event);

      // Then
      expect(result).toBe(event);
      expect(result).toMatchObject({
        tags: {
          actionability: "actionable",
          kind: "runtime",
        },
      });
    });

    it("should keep fatal runtime messages that mention status without HTTP context", () => {
      // Given
      const event = {
        level: "fatal",
        message: "State transition status 403 caused worker crash",
      };

      // When
      const result = applySentryEventPolicy(event);

      // Then
      expect(result).toBe(event);
      expect(result).toMatchObject({
        tags: {
          actionability: "actionable",
          kind: "runtime",
        },
      });
    });

    it("should keep fatal runtime messages that mention status code without HTTP context", () => {
      // Given
      const event = {
        level: "fatal",
        message: "State transition status code 403 caused worker crash",
      };

      // When
      const result = applySentryEventPolicy(event);

      // Then
      expect(result).toBe(event);
      expect(result).toMatchObject({
        tags: {
          actionability: "actionable",
          kind: "runtime",
        },
      });
    });

    it("should keep fatal runtime messages that mention response without HTTP context", () => {
      // Given
      const event = {
        level: "fatal",
        message: "Worker response 404 triggered fatal cache corruption",
      };

      // When
      const result = applySentryEventPolicy(event);

      // Then
      expect(result).toBe(event);
      expect(result).toMatchObject({
        tags: {
          actionability: "actionable",
          kind: "runtime",
        },
      });
    });

    it("should preserve existing tags on actionable API events", () => {
      // Given
      const event = {
        level: "error",
        message: "API response failed with status 500",
        tags: {
          feature: "providers",
          status_code: "500",
        },
      };

      // When
      const result = applySentryEventPolicy(event, undefined, {
        source: "server_action",
      });

      // Then
      expect(result).toBe(event);
      expect(result).toMatchObject({
        tags: {
          actionability: "actionable",
          feature: "providers",
          kind: "api",
          source: "server_action",
          status_code: "500",
        },
      });
    });
  });

  describe("when events are non-actionable", () => {
    it("should drop warning events", () => {
      // Given
      const event = { level: "warning", message: "Provider already exists" };

      // When
      const result = applySentryEventPolicy(event);

      // Then
      expect(result).toBeNull();
    });

    it("should drop Next.js redirect control-flow events", () => {
      // Given
      const event = { level: "error", message: "NEXT_REDIRECT" };

      // When
      const result = applySentryEventPolicy(event);

      // Then
      expect(result).toBeNull();
    });

    it("should drop AbortError events", () => {
      // Given
      const event = { level: "error", message: "The operation was aborted" };
      const hint: SentryEventHint = {
        originalException: new DOMException("Aborted", "AbortError"),
      };

      // When
      const result = applySentryEventPolicy(event, hint);

      // Then
      expect(result).toBeNull();
    });

    it("should drop expected HTTP 401 events", () => {
      // Given
      const event = { level: "error", tags: { status_code: "401" } };

      // When
      const result = applySentryEventPolicy(event);

      // Then
      expect(result).toBeNull();
    });

    it("should drop expected HTTP 403 events", () => {
      // Given
      const event = { level: "error", message: "Request failed with 403" };

      // When
      const result = applySentryEventPolicy(event);

      // Then
      expect(result).toBeNull();
    });

    it("should drop expected HTTP 404 events", () => {
      // Given
      const event = { level: "error" };
      const hint = { originalException: { status: 404 } };

      // When
      const result = applySentryEventPolicy(event, hint);

      // Then
      expect(result).toBeNull();
    });

    it("should drop clear HTTP messages with expected status codes", () => {
      // Given
      const event = {
        level: "error",
        message: "HTTP response status code 404",
      };

      // When
      const result = applySentryEventPolicy(event);

      // Then
      expect(result).toBeNull();
    });

    it("should drop already-reported errors", () => {
      // Given
      const error = new Error("Already reported failure");
      const event = { level: "error", message: error.message };
      markErrorAsReported(error);

      // When
      const result = applySentryEventPolicy(event, {
        originalException: error,
      });

      // Then
      expect(isErrorAlreadyReported(error)).toBe(true);
      expect(result).toBeNull();
    });
  });
});
