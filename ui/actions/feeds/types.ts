// Feed type definitions using const-based pattern

export const FEED_SOURCE_TYPES = {
  GITHUB_RELEASES: "github_releases",
  BLOG: "blog",
  CUSTOM: "custom",
} as const;

export type FeedSourceType =
  (typeof FEED_SOURCE_TYPES)[keyof typeof FEED_SOURCE_TYPES];

export interface FeedSource {
  id: string;
  name: string;
  type: FeedSourceType;
  url: string;
  enabled: boolean;
}

export interface FeedItem {
  id: string;
  title: string;
  description: string;
  link: string;
  pubDate: string; // ISO 8601 format
  sourceId: string;
  sourceName: string;
  sourceType: FeedSourceType;
  author?: string;
  categories?: string[];
  contentSnippet?: string;
}

export interface ParsedFeed {
  items: FeedItem[];
  totalCount: number;
  sources: FeedSource[];
}

export interface FeedError {
  message: string;
  sourceId?: string;
  sourceName?: string;
}
