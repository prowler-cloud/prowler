import type { Config } from "driver.js";

export const TOUR_THEMES = {
  LIGHT: "light",
  DARK: "dark",
} as const;

export type TourTheme = (typeof TOUR_THEMES)[keyof typeof TOUR_THEMES];

export const TOUR_OVERLAY_COLORS = {
  [TOUR_THEMES.LIGHT]: "#0f172a",
  [TOUR_THEMES.DARK]: "#0a0a0a",
} as const;

/**
 * Global defaults shared by every tour. Per-step overrides go on
 * the step itself; per-tour overrides are merged in by `getDriverConfig`.
 *
 * Values are the final decisions from this change's design doc.
 */
export const baseDriverConfig: Config = {
  popoverClass: "prowler-theme",
  animate: true,
  smoothScroll: true,
  allowClose: true,
  overlayClickBehavior: "close",
  overlayOpacity: 0.72,
  stagePadding: 10,
  stageRadius: 10,
  popoverOffset: 12,
  showButtons: ["next", "previous", "close"],
  showProgress: true,
  progressText: "Step {{current}} of {{total}}",
  nextBtnText: "Next",
  prevBtnText: "Back",
  doneBtnText: "Got it",
  allowKeyboardControl: true,
  disableActiveInteraction: false,
};

/**
 * Build a driver.js `Config` for the active theme, optionally merging in
 * per-tour overrides. `overlayColor` is the one knob driver.js exposes only
 * via JS (no CSS variable hook), so we resolve it from `useTheme()` at the
 * call site and pass it in here.
 */
export function getDriverConfig(
  theme: TourTheme,
  overrides?: Partial<Config>,
): Config {
  return {
    ...baseDriverConfig,
    overlayColor: TOUR_OVERLAY_COLORS[theme],
    ...(overrides ?? {}),
  };
}
