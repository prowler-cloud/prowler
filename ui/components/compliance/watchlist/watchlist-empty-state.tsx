import { Pin } from "lucide-react";

import { Alert, AlertDescription } from "@/components/shadcn/alert";

/** Default copy: what an uncurated watchlist reads like on any surface. The
 *  two Multiple Scans sections override it to name what is missing there. */
const WATCHLIST_FILTER_EMPTY_HINT =
  "No frameworks pinned yet. Pin the ones your organization tracks — from a card or the watchlist selector — or clear the filter to browse the full catalog.";

interface WatchlistEmptyStateProps {
  message?: string;
}

/**
 * What a surface renders when the watchlist filter hides everything it had.
 *
 * `role="status"` overrides the component's default `role="alert"`: this is
 * the expected result of a filter the user just applied, not an error, and an
 * assertive live region would interrupt to announce it — twice over on the
 * Multiple Scans tab, which renders two sections.
 */
export const WatchlistEmptyState = ({
  message = WATCHLIST_FILTER_EMPTY_HINT,
}: WatchlistEmptyStateProps) => (
  <Alert role="status" variant="info">
    <Pin aria-hidden />
    <AlertDescription>{message}</AlertDescription>
  </Alert>
);
