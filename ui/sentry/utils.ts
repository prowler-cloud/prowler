import * as Sentry from "@sentry/nextjs";

import { auth } from "@/auth.config";

/**
 * Set user context in Sentry from the current session
 * This should be called after successful authentication
 */
export async function setSentryUser() {
  try {
    const session = await auth();

    if (session?.user) {
      Sentry.setUser({
        id: session.user.id,
        email: session.user.email || undefined,
        username: session.user.name || undefined,
        tenant_id: session.tenantId,
      });

      Sentry.setContext("session", {
        tenantId: session.tenantId,
        accessToken: session.accessToken ? "present" : "missing",
        refreshToken: session.refreshToken ? "present" : "missing",
      });
    } else {
      // Clear user context on logout
      Sentry.setUser(null);
    }
  } catch (error) {
    console.error("Failed to set Sentry user context:", error);
  }
}

/**
 * Add breadcrumb for user actions
 */
export function addBreadcrumb(
  message: string,
  category: string,
  data?: Record<string, any>,
) {
  Sentry.addBreadcrumb({
    message,
    category,
    level: "info",
    data,
    timestamp: Date.now(),
  });
}

/**
 * Capture a message with context
 */
export function captureMessage(
  message: string,
  level: Sentry.SeverityLevel = "info",
  context?: Record<string, any>,
) {
  Sentry.captureMessage(message, {
    level,
    extra: context,
  });
}

/**
 * Wrapper for server actions to capture errors
 */
export async function withSentry<T extends (...args: any[]) => Promise<any>>(
  fn: T,
  actionName: string,
): Promise<T> {
  return (async (...args: Parameters<T>) => {
    try {
      addBreadcrumb(`Server action: ${actionName}`, "server.action", {
        actionName,
        timestamp: new Date().toISOString(),
      });

      // Execute the function
      const result = await fn(...args);
      return result;
    } catch (error) {
      // Capture the error with context
      Sentry.captureException(error, {
        tags: {
          action_name: actionName,
          error_source: "server_action",
        },
        contexts: {
          action: {
            name: actionName,
            args: JSON.stringify(args).slice(0, 1000), // Limit size
          },
        },
      });

      // Re-throw the error to maintain normal flow
      throw error;
    }
  }) as T;
}
