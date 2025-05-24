import { getCurrentUserId } from "@/lib/lighthouse/cache";
import { fetchNudges, nudgeCache } from "@/lib/lighthouse/nudge";

import { LighthouseBanner } from "./lighthouse-banner";

async function getNudges() {
  try {
    const userId = await getCurrentUserId();

    // Check if we have cached nudges
    if (nudgeCache[userId]?.nudges) {
      // Return cached nudges
      return nudgeCache[userId].nudges;
    }

    // If we're already fetching nudges, return default nudges
    if (nudgeCache[userId]?.isFetching) {
      return { nudges: [] };
    }

    // Initialize cache entry and start fetching
    nudgeCache[userId] = {
      nudges: null,
      timestamp: Date.now(),
      isFetching: true,
    };

    // Start fetching nudges asynchronously
    fetchNudges(userId).catch(console.error);

    // Return default nudges while fetching
    return { nudges: [] };
  } catch (error) {
    console.error("Error getting nudges:", error);
    return { nudges: [] };
  }
}

export async function LighthouseBannerWrapper() {
  const nudges = await getNudges();

  return <LighthouseBanner initialNudges={nudges} />;
}
