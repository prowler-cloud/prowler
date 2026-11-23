import type { RealtimePolicy } from "@/app/(prowler)/realtime/_types";

/** Shown on write controls while sample data is on screen. */
export const DEMO_TOOLTIP = "Not available on demo data";

/** Shown on write controls when the role cannot change Realtime. */
export const NO_PERMISSION_TOOLTIP =
  "Your role needs the Manage Realtime permission.";

/**
 * The dashboard shows sample data only while the account has no policy. A
 * paused policy still shows the account's own history.
 */
export const isRealtimeDemo = (policy: RealtimePolicy | null): boolean =>
  policy === null;
