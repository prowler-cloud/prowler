import type { LighthouseV2Configuration } from "@/app/(prowler)/lighthouse/_types";
import { LIGHTHOUSE_ROUTE } from "@/lib/lighthouse-routes";
import type { ServerActionResult } from "@/types/server-actions";

// Auto-submitted as the first message of a new conversation: /lighthouse reads
// ?prompt= and sends it once on mount (see LighthouseV2ChatPage).
export const LIGHTHOUSE_OVERVIEW_BANNER_PROMPT =
  "Find and guide me to remediate what actually matters. What do I have to do today to be secure?";

export const LIGHTHOUSE_OVERVIEW_BANNER_HREF = {
  CHAT: `${LIGHTHOUSE_ROUTE.CHAT}?prompt=${encodeURIComponent(LIGHTHOUSE_OVERVIEW_BANNER_PROMPT)}`,
  SETTINGS: LIGHTHOUSE_ROUTE.SETTINGS,
} as const;

export type LighthouseOverviewBannerHref =
  (typeof LIGHTHOUSE_OVERVIEW_BANNER_HREF)[keyof typeof LIGHTHOUSE_OVERVIEW_BANNER_HREF];

type LoadLighthouseV2Configurations = () => Promise<
  ServerActionResult<LighthouseV2Configuration[]>
>;

export function resolveLighthouseOverviewBannerHref(
  configurations: LighthouseV2Configuration[],
): LighthouseOverviewBannerHref {
  return configurations.some(
    (configuration) => configuration.connected === true,
  )
    ? LIGHTHOUSE_OVERVIEW_BANNER_HREF.CHAT
    : LIGHTHOUSE_OVERVIEW_BANNER_HREF.SETTINGS;
}

export async function getLighthouseOverviewBannerHref(
  cloud: boolean,
  loadConfigurations: LoadLighthouseV2Configurations,
): Promise<LighthouseOverviewBannerHref | null> {
  if (!cloud) {
    return null;
  }

  const result = await loadConfigurations();
  if (!("data" in result)) {
    return null;
  }

  return resolveLighthouseOverviewBannerHref(result.data);
}
