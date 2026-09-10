import { describe, expect, it } from "vitest";

import { filterWarningSentryEvent } from "./sentry-event-filter";

describe("filterWarningSentryEvent", () => {
  describe("when the event level is warning", () => {
    it("should drop the event", () => {
      // Given
      const event = { level: "warning", message: "Provider already exists" };

      // When
      const result = filterWarningSentryEvent(event);

      // Then
      expect(result).toBeNull();
    });
  });

  describe("when the event level is actionable", () => {
    it("should keep error events", () => {
      // Given
      const event = { level: "error", message: "Unexpected failure" };

      // When
      const result = filterWarningSentryEvent(event);

      // Then
      expect(result).toBe(event);
    });

    it("should keep fatal events", () => {
      // Given
      const event = { level: "fatal", message: "Runtime crashed" };

      // When
      const result = filterWarningSentryEvent(event);

      // Then
      expect(result).toBe(event);
    });

    it("should keep events without a level", () => {
      // Given
      const event = { message: "Default Sentry event" };

      // When
      const result = filterWarningSentryEvent(event);

      // Then
      expect(result).toBe(event);
    });
  });
});
