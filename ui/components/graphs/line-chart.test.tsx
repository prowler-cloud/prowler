import { describe, expect, it } from "vitest";

import { formatYAxisTick } from "./line-chart.utils";

describe("formatYAxisTick", () => {
  describe("when findings counts are large", () => {
    it("should compact six-digit values so Y-axis labels do not overflow", () => {
      // Given
      const tickValue = 150000;

      // When
      const formattedValue = formatYAxisTick(tickValue);

      // Then
      expect(formattedValue).toBe("150K");
    });

    it("should compact million-scale values", () => {
      // Given
      const tickValue = 1200000;

      // When
      const formattedValue = formatYAxisTick(tickValue);

      // Then
      expect(formattedValue).toBe("1.2M");
    });
  });

  describe("when findings counts are small", () => {
    it("should keep values below 1000 readable without compact notation", () => {
      // Given
      const tickValue = 999;

      // When
      const formattedValue = formatYAxisTick(tickValue);

      // Then
      expect(formattedValue).toBe("999");
    });
  });
});
