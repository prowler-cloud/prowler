export const OVERVIEW_BANNER_VARIANT = {
  LIGHTHOUSE: "lighthouse",
  AGENTS: "agents",
} as const;

export type OverviewBannerVariant =
  (typeof OVERVIEW_BANNER_VARIANT)[keyof typeof OVERVIEW_BANNER_VARIANT];
