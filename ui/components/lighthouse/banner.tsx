import { isLighthouseConfigured } from "@/actions/lighthouse/lighthouse";

import { LighthouseBannerClient } from "./banner-client";

export const LighthouseBanner = async () => {
  try {
    const isConfigured = await isLighthouseConfigured();

    return <LighthouseBannerClient isConfigured={isConfigured} />;
  } catch (error) {
    return null;
  }
};
