import { fetchFeeds } from "@/actions/feeds";
import { FeedsClient } from "@/components/feeds";

export const FeedsServer = async () => {
  const feeds = await fetchFeeds();

  return <FeedsClient initialFeeds={feeds} />;
};
