import { fetchFeeds } from "@/actions/feeds";

import { FeedsClient } from "./feeds-client";

interface FeedsServerProps {
  limit?: number;
}

export async function FeedsServer({ limit = 15 }: FeedsServerProps) {
  try {
    const feedData = await fetchFeeds(limit);

    return <FeedsClient feedData={feedData} />;
  } catch (error) {
    console.error("Error fetching feeds in server component:", error);

    // Return client component with error state
    return (
      <FeedsClient
        feedData={{
          items: [],
          totalCount: 0,
          sources: [],
        }}
        error="Failed to load feeds"
      />
    );
  }
}
