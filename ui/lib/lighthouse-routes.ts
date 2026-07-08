// Single source of truth for Lighthouse routes: server actions revalidate
// these exact paths, so navigation hrefs and revalidatePath must not diverge.
export const LIGHTHOUSE_ROUTE = {
  CHAT: "/lighthouse",
  SETTINGS: "/lighthouse/settings",
} as const;

export type LighthouseRoute =
  (typeof LIGHTHOUSE_ROUTE)[keyof typeof LIGHTHOUSE_ROUTE];

// The full-page chat route (and its subpaths) owns the Lighthouse chat: the
// global side panel does not exist there. Segment-aware so sibling routes
// (e.g. a future /lighthouse-foo) never match.
export function isLighthouseChatRoute(pathname: string | null): boolean {
  if (!pathname) return false;
  return (
    pathname === LIGHTHOUSE_ROUTE.CHAT ||
    pathname.startsWith(`${LIGHTHOUSE_ROUTE.CHAT}/`)
  );
}
