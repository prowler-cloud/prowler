"use server";

import { extract } from "@extractus/feed-extractor";
import { unstable_cache } from "next/cache";
import { z } from "zod";

import type { FeedError, FeedItem, FeedSource, ParsedFeed } from "./types";
import { FEED_SOURCE_TYPES } from "./types";

const feedSourceSchema = z.object({
  id: z.string().min(1),
  name: z.string().min(1),
  type: z.enum([
    FEED_SOURCE_TYPES.GITHUB_RELEASES,
    FEED_SOURCE_TYPES.BLOG,
    FEED_SOURCE_TYPES.CUSTOM,
  ]),
  url: z.url(),
  enabled: z.boolean(),
});

const feedSourcesSchema = z.array(feedSourceSchema);

// Parse feed sources from environment variable
function getFeedSources(): FeedSource[] {
  const feedSourcesEnv = process.env.RSS_FEED_SOURCES;

  if (!feedSourcesEnv || feedSourcesEnv.trim().length === 0) {
    return [];
  }

  try {
    const parsed = JSON.parse(feedSourcesEnv);
    const validated = feedSourcesSchema.parse(parsed);
    return validated.filter((source) => source.enabled);
  } catch {
    return [];
  }
}

// Parse a single RSS/Atom feed
async function parseSingleFeed(
  source: FeedSource,
): Promise<{ items: FeedItem[]; error?: FeedError }> {
  try {
    const feed = await extract(source.url);

    const items: FeedItem[] = (feed.entries || []).map((entry) => ({
      id: entry.id || entry.link || `${source.id}-${entry.title}`,
      title: entry.title || "Untitled",
      description: entry.description || "",
      link: entry.link || "",
      pubDate: entry.published
        ? new Date(entry.published).toISOString()
        : new Date().toISOString(),
      sourceId: source.id,
      sourceName: source.name,
      sourceType: source.type,
      author: undefined,
      categories: [],
      contentSnippet: entry.description?.slice(0, 500),
    }));

    return { items };
  } catch (error) {
    return {
      items: [],
      error: {
        message: error instanceof Error ? error.message : "Unknown error",
        sourceId: source.id,
        sourceName: source.name,
      },
    };
  }
}

// Fetch and parse all enabled feeds
async function fetchAllFeeds(): Promise<ParsedFeed> {
  const sources = getFeedSources();

  if (sources.length === 0) {
    return {
      items: [],
      totalCount: 0,
      sources: [],
    };
  }

  // Fetch all feeds in parallel
  const results = await Promise.all(
    sources.map((source) => parseSingleFeed(source)),
  );

  // Combine all items from all sources (errors are handled gracefully by returning empty items)
  const allItems: FeedItem[] = results.flatMap((result) => result.items);

  // Sort by publication date (newest first)
  allItems.sort(
    (a, b) => new Date(b.pubDate).getTime() - new Date(a.pubDate).getTime(),
  );

  return {
    items: allItems,
    totalCount: allItems.length,
    sources,
  };
}

// Cached version of fetchAllFeeds with 5-minute revalidation
const getCachedFeeds = unstable_cache(
  async () => fetchAllFeeds(),
  ["rss-feeds"],
  {
    revalidate: 300, // 5 minutes
    tags: ["feeds"],
  },
);

// Public API: Fetch feeds with optional limit
export async function fetchFeeds(limit?: number): Promise<ParsedFeed> {
  const allFeeds = await getCachedFeeds();

  if (limit && limit > 0) {
    return {
      ...allFeeds,
      items: allFeeds.items.slice(0, limit),
    };
  }

  return allFeeds;
}
