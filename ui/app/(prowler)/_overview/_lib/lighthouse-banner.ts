import type { LighthouseV2Configuration } from "@/app/(prowler)/lighthouse/_types";

export const LIGHTHOUSE_OVERVIEW_BANNER_HREF = {
  CHAT: "/lighthouse",
  SETTINGS: "/lighthouse/settings",
} as const;

export type LighthouseOverviewBannerHref =
  (typeof LIGHTHOUSE_OVERVIEW_BANNER_HREF)[keyof typeof LIGHTHOUSE_OVERVIEW_BANNER_HREF];

interface LighthouseV2ConfigurationsSuccess {
  data: LighthouseV2Configuration[];
}

interface LighthouseV2ConfigurationsFailure {
  error: string;
  errors?: unknown[];
  status?: number;
}

type LighthouseV2ConfigurationsResult =
  | LighthouseV2ConfigurationsSuccess
  | LighthouseV2ConfigurationsFailure;

type LoadLighthouseV2Configurations =
  () => Promise<LighthouseV2ConfigurationsResult>;

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
