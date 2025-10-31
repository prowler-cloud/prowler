"use server";

import { unstable_cache } from "next/cache";
import Parser from "rss-parser";
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
  const parser = new Parser({
    timeout: 10000,
    headers: {
      "User-Agent": "Prowler-UI/1.0",
    },
  });

  try {
    const feed = await parser.parseURL(source.url);

    // Map RSS items to our FeedItem type
    const items: FeedItem[] = (feed.items || []).map((item) => {
      // Validate and parse date with fallback to current date
      const parsePubDate = (): string => {
        const dateString = item.isoDate || item.pubDate;
        if (!dateString) return new Date().toISOString();

        const parsed = new Date(dateString);
        return isNaN(parsed.getTime())
          ? new Date().toISOString()
          : parsed.toISOString();
      };

      return {
        id: item.guid || item.link || `${source.id}-${item.title}`,
        title: item.title || "Untitled",
        description:
          item.contentSnippet || item.content || item.description || "",
        link: item.link || "",
        pubDate: parsePubDate(),
        source: {
          id: source.id,
          name: source.name,
          type: source.type,
        },
        author: item.creator || item.author,
        categories: item.categories || [],
        contentSnippet: item.contentSnippet || undefined,
      };
    });

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
    // eslint-disable-next-line no-console
    console.warn("No RSS feed sources configured");
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

  // Combine all items from all sources
  const allItems: FeedItem[] = [];
  const errors: FeedError[] = [];

  results.forEach((result) => {
    allItems.push(...result.items);
    if (result.error) {
      errors.push(result.error);
    }
  });

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
