import type { Config } from "driver.js";

import { renderTourPopover } from "./tour-popover-render";

export const TOUR_THEMES = {
  LIGHT: "light",
  DARK: "dark",
} as const;

export type TourTheme = (typeof TOUR_THEMES)[keyof typeof TOUR_THEMES];

export const TOUR_OVERLAY_COLORS = {
  [TOUR_THEMES.LIGHT]: "#0f172a",
  [TOUR_THEMES.DARK]: "#0a0a0a",
} as const;

// Per-step overrides go on the step; per-tour overrides merge in via getDriverConfig.
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
  onPopoverRender: renderTourPopover,
};

// driver.js exposes `overlayColor` only via JS (no CSS variable hook), so the
// theme is resolved at the call site and passed in here.
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
