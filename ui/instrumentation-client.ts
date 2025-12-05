/**
 * Next.js Client Instrumentation
 *
 * This file runs on the client before React hydration.
 * Used to set up navigation progress tracking.
 *
 * @see https://nextjs.org/docs/app/api-reference/file-conventions/instrumentation-client
 */

import {
  cancelProgress,
  startProgress,
} from "@/components/ui/navigation-progress/use-navigation-progress";

const NAVIGATION_TYPE = {
  PUSH: "push",
  REPLACE: "replace",
  TRAVERSE: "traverse",
} as const;

type NavigationType = (typeof NAVIGATION_TYPE)[keyof typeof NAVIGATION_TYPE];

/**
 * Called by Next.js when router navigation begins.
 * Triggers the navigation progress bar.
 */
export function onRouterTransitionStart(
  url: string,
  _navigationType: NavigationType,
) {
  // Check if navigating to the same URL (only pathname, ignore query params for this check)
  const targetPath = url.split("?")[0];
  const currentPath = window.location.pathname;

  if (targetPath === currentPath && url === window.location.href) {
    // Same URL - cancel any ongoing progress
    cancelProgress();
  } else {
    // Different URL - start progress
    startProgress();
  }
}
