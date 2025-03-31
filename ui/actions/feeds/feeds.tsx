"use server";

import Parser from "rss-parser";

// TODO: Need to use the actual feed url
const RSS_FEED_URL = "https://prowler.com/blog/rss";

export const fetchFeeds = async (): Promise<any | any[]> => {
  const parser = new Parser();
  try {
    const feed = await parser.parseURL(RSS_FEED_URL);
    return [
      {
        title: feed.title,
        description: feed.description,
        link: feed.link,
        lastBuildDate: new Date(feed.lastBuildDate).toLocaleString(),
      },
    ];
  } catch (error) {
    // eslint-disable-next-line no-console
    console.error("Error fetching RSS feed:", error);
    return [];
  }
};
