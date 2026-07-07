import { differenceInCalendarDays, format, isValid, parseISO } from "date-fns";

import { formatLocalDate } from "@/lib/date-utils";

// Chat bubble timestamp, e.g. "Monday 9:30 AM".
export function formatMessageTimestamp(insertedAt: string): string {
  const date = new Date(insertedAt);
  if (Number.isNaN(date.getTime())) {
    return "";
  }
  return format(date, "EEEE h:mm a");
}

// Provider connection "last checked" label, reusing the app-wide local date
// format (e.g. "Jun 15, 2026") instead of a bespoke toLocaleDateString call.
export function formatLastChecked(value?: string | null): string {
  if (!value) return "Never checked";
  const formatted = formatLocalDate(value);
  return formatted ? `Last checked ${formatted}` : "Last check unavailable";
}

// Relative age for the session history list, e.g. "Today", "1 day", "5 days".
export function formatSessionAge(dateString: string): string {
  const date = parseISO(dateString);
  if (!isValid(date)) return "";

  const ageInDays = Math.max(0, differenceInCalendarDays(new Date(), date));
  if (ageInDays === 0) return "Today";
  return ageInDays === 1 ? "1 day" : `${ageInDays} days`;
}
