import type { LighthouseV2Configuration } from "@/app/(prowler)/lighthouse/_types";
import { LIGHTHOUSE_ROUTE } from "@/lib/lighthouse-routes";
import type { ServerActionResult } from "@/types/server-actions";

export const LIGHTHOUSE_OVERVIEW_BANNER_HREF = LIGHTHOUSE_ROUTE;

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
