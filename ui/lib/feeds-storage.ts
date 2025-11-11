// Utility functions for managing feed state in localStorage

const STORAGE_KEY = "prowler-feeds-last-seen";

interface FeedStorage {
  lastSeenIds: string[];
  lastCheckTimestamp: number;
}

/**
 * Get the last seen feed IDs from localStorage
 */
export function getLastSeenFeedIds(): string[] {
  if (typeof window === "undefined") return [];

  try {
    const stored = localStorage.getItem(STORAGE_KEY);
    if (!stored) return [];

    const data: FeedStorage = JSON.parse(stored);
    return data.lastSeenIds || [];
  } catch {
    return [];
  }
}

/**
 * Save the current feed IDs as seen
 */
export function markFeedsAsSeen(feedIds: string[]): void {
  if (typeof window === "undefined") return;

  try {
    const data: FeedStorage = {
      lastSeenIds: feedIds,
      lastCheckTimestamp: Date.now(),
    };
    localStorage.setItem(STORAGE_KEY, JSON.stringify(data));
  } catch {
    // Silently fail if localStorage is unavailable
  }
}

/**
 * Check if there are new feeds (feeds that haven't been seen before)
 */
export function hasNewFeeds(currentFeedIds: string[]): boolean {
  const lastSeenIds = getLastSeenFeedIds();

  // If no feeds stored, everything is new
  if (lastSeenIds.length === 0 && currentFeedIds.length > 0) {
    return true;
  }

  // Check if there are any current feeds not in the last seen list
  return currentFeedIds.some((id) => !lastSeenIds.includes(id));
}
