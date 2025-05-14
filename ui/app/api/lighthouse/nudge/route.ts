import { getCurrentUserId } from "@/lib/lighthouse/cache";
import { fetchNudges, nudgeCache } from "@/lib/lighthouse/nudge";

export async function GET() {
  try {
    const userId = await getCurrentUserId();

    // Check if we have cached nudges
    if (nudgeCache[userId]?.nudges) {
      // Return cached nudges
      return Response.json(nudgeCache[userId].nudges);
    }

    // If we're already fetching nudges, return default nudges
    if (nudgeCache[userId]?.isFetching) {
      return Response.json({ nudges: [] });
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
    return Response.json({ nudges: [] });
  } catch (error) {
    console.error("Error in GET request:", error);
    return Response.json({ error: "An error occurred" }, { status: 500 });
  }
}
