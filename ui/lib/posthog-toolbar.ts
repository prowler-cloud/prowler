import type { PostHogInterface } from "posthog-js";

declare global {
  interface Window {
    posthog?: PostHogInterface;
  }
}

export function exposePosthogForToolbar(client: PostHogInterface): void {
  if (process.env.NODE_ENV === "development") window.posthog = client;
}
