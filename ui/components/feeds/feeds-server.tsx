import { fetchFeeds } from "@/actions/feeds";

import { FeedsClient } from "./feeds-client";

interface FeedsServerProps {
  limit?: number;
}

export async function FeedsServer({ limit = 15 }: FeedsServerProps) {
  const feedData = await fetchFeeds(limit);
  return <FeedsClient feedData={feedData} />;
}
