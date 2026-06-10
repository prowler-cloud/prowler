import { format, formatDistanceToNow, parseISO } from "date-fns";

/**
 * Formats an ISO string or Date into a `yyyy-MM-dd` string in the user's local
 * timezone. Mirrors the format used by `DateWithTime`, so UI chips/URLs built
 * with this helper match what the user sees in tables and pickers. Returns
 * undefined for null, empty, or malformed input so callers can guard on it
 * (e.g. `isDisabled={!toLocalDateString(x)}`). Do NOT use this for UTC-based
 * date bucketing (e.g. chart axes partitioned server-side by UTC day) — that
 * use case needs a separate UTC helper.
 */
export function toLocalDateString(
  value: string | Date | null | undefined,
): string | undefined {
  if (!value) return undefined;
  try {
    const date = typeof value === "string" ? parseISO(value) : value;
    if (isNaN(date.getTime())) return undefined;
    return format(date, "yyyy-MM-dd");
  } catch {
    return undefined;
  }
}

/** Local date in the app's table format (e.g. "Jun 15, 2026"), as shown by DateWithTime. */
export function formatLocalDate(
  value: string | null | undefined,
): string | undefined {
  if (!value) return undefined;
  try {
    const date = parseISO(value);
    if (isNaN(date.getTime())) return undefined;
    return format(date, "MMM dd, yyyy");
  } catch {
    return undefined;
  }
}

/** Local time with the browser's short zone label (e.g. "12:00AM MAD"), as shown by DateWithTime. */
export function formatLocalTimeWithZone(
  value: string | null | undefined,
): string | undefined {
  if (!value) return undefined;
  try {
    const date = parseISO(value);
    if (isNaN(date.getTime())) return undefined;
    const zone =
      Intl.DateTimeFormat()
        .resolvedOptions()
        .timeZone.split("/")
        .pop()
        ?.substring(0, 3)
        .toUpperCase() || "";
    return `${format(date, "h:mma")} ${zone}`.trim();
  } catch {
    return undefined;
  }
}

/**
 * Formats a duration in seconds to a human-readable string like "2h 5m 30s".
 */
export function formatDuration(seconds: number): string {
  const hours = Math.floor(seconds / 3600);
  const minutes = Math.floor((seconds % 3600) / 60);
  const remainingSeconds = seconds % 60;

  const parts = [];
  if (hours > 0) parts.push(`${hours}h`);
  if (minutes > 0) parts.push(`${minutes}m`);
  if (remainingSeconds > 0 || parts.length === 0)
    parts.push(`${remainingSeconds}s`);

  return parts.join(" ");
}

/**
 * Formats a date string to a relative time like "3 days ago".
 * Returns the fallback string if the date is null.
 */
export function formatRelativeTime(
  date: string | null,
  fallback = "Never",
): string {
  if (!date) return fallback;
  return formatDistanceToNow(new Date(date), { addSuffix: true });
}

/**
 * Computes a human-readable "failing for" duration from first_seen_at to now.
 * Returns null if the date is invalid or not provided.
 */
export function getFailingForLabel(firstSeenAt: string | null): string | null {
  if (!firstSeenAt) return null;

  const start = new Date(firstSeenAt);
  if (isNaN(start.getTime())) return null;

  const now = new Date();
  const diffMs = now.getTime() - start.getTime();
  if (diffMs < 0) return null;

  const diffDays = Math.floor(diffMs / (1000 * 60 * 60 * 24));

  if (diffDays < 1) return "< 1 day";
  if (diffDays < 30) return `${diffDays} day${diffDays > 1 ? "s" : ""}`;

  const diffMonths = Math.floor(diffDays / 30);
  if (diffMonths < 12) return `${diffMonths} month${diffMonths > 1 ? "s" : ""}`;

  const diffYears = Math.floor(diffMonths / 12);
  return `${diffYears} year${diffYears > 1 ? "s" : ""}`;
}
