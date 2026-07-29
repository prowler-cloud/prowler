import { describe, expect, it } from "vitest";

import {
  baseDriverConfig,
  getDriverConfig,
  TOUR_OVERLAY_COLORS,
  TOUR_THEMES,
} from "./tour-config";

describe("getDriverConfig", () => {
  it("returns dark overlay color for the dark theme", () => {
    const config = getDriverConfig(TOUR_THEMES.DARK);
    expect(config.overlayColor).toBe(TOUR_OVERLAY_COLORS[TOUR_THEMES.DARK]);
  });

  it("returns light overlay color for the light theme", () => {
    const config = getDriverConfig(TOUR_THEMES.LIGHT);
    expect(config.overlayColor).toBe(TOUR_OVERLAY_COLORS[TOUR_THEMES.LIGHT]);
  });

  it("preserves base config defaults when no overrides are passed", () => {
    const config = getDriverConfig(TOUR_THEMES.LIGHT);

    expect(config.popoverClass).toBe("prowler-theme");
    expect(config.showProgress).toBe(true);
    expect(config.progressText).toBe("Step {{current}} of {{total}}");
    expect(config.prevBtnText).toBe("Back");
    expect(config.doneBtnText).toBe("Got it");
    expect(config.stagePadding).toBe(baseDriverConfig.stagePadding);
  });

  it("merges overrides on top of the base config", () => {
    const config = getDriverConfig(TOUR_THEMES.LIGHT, {
      stagePadding: 24,
      doneBtnText: "Finish",
    });

    expect(config.stagePadding).toBe(24);
    expect(config.doneBtnText).toBe("Finish");
    expect(config.popoverClass).toBe("prowler-theme");
  });

  it("lets overrides win over the theme-derived overlayColor", () => {
    const config = getDriverConfig(TOUR_THEMES.LIGHT, {
      overlayColor: "#abcdef",
    });

    expect(config.overlayColor).toBe("#abcdef");
  });

  it("does not mutate the shared baseDriverConfig", () => {
    const snapshot = { ...baseDriverConfig };
    getDriverConfig(TOUR_THEMES.DARK, { stagePadding: 99 });
    expect(baseDriverConfig).toEqual(snapshot);
  });
});
