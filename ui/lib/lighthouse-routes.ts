// Single source of truth for Lighthouse routes: server actions revalidate
// these exact paths, so navigation hrefs and revalidatePath must not diverge.
export const LIGHTHOUSE_ROUTE = {
  CHAT: "/lighthouse",
  SETTINGS: "/lighthouse/settings",
} as const;

export type LighthouseRoute =
  (typeof LIGHTHOUSE_ROUTE)[keyof typeof LIGHTHOUSE_ROUTE];
