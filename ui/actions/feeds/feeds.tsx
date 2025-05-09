"use server";

import Parser from "rss-parser";

const RSS_FEED_URL = process.env.RSS_FEED_URL || "";

export const fetchFeeds = async (): Promise<any | any[]> => {
  const parser = new Parser();
  try {
    // TODO: Need to update return logic when actual URL is updated for RSS FEED
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
