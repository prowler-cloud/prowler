/**
 * Sentry Breadcrumb Utilities
 *
 * Provides helper functions to add breadcrumbs for tracking critical paths
 * and user actions throughout the application.
 *
 * Usage:
 * ```typescript
 * import { addUserAction, addApiCall, addTaskEvent } from '@/lib/sentry-breadcrumbs';
 *
 * addUserAction('clicked_create_scan', { provider: 'aws' });
 * addApiCall('POST /scans', 'success');
 * addTaskEvent('scan_started', 'scan-123');
 * ```
 */

import * as Sentry from "@sentry/nextjs";

export interface BreadcrumbContext {
  [key: string]: string | number | boolean | undefined;
}

/**
 * Add breadcrumb for user actions
 * @param action - User action identifier
 * @param context - Additional context data
 */
export function addUserAction(action: string, context?: BreadcrumbContext) {
  Sentry.addBreadcrumb({
    message: `User action: ${action}`,
    category: "user.action",
    level: "info",
    data: context,
  });
}

/**
 * Add breadcrumb for API calls
 * @param endpoint - API endpoint (e.g., "GET /scans")
 * @param status - Status of the call (success, error, timeout)
 * @param context - Additional context data
 */
export function addApiCall(
  endpoint: string,
  status: "success" | "error" | "timeout",
  context?: BreadcrumbContext,
) {
  Sentry.addBreadcrumb({
    message: `API ${endpoint}`,
    category: "api",
    level: status === "error" ? "warning" : "info",
    data: {
      status,
      ...context,
    },
  });
}

/**
 * Add breadcrumb for task events
 * @param event - Task event (started, completed, failed)
 * @param taskId - Task identifier
 * @param context - Additional context data
 */
export function addTaskEvent(
  event: "started" | "completed" | "failed" | "timeout",
  taskId: string,
  context?: BreadcrumbContext,
) {
  Sentry.addBreadcrumb({
    message: `Task ${event}: ${taskId}`,
    category: "task",
    level: event === "failed" ? "warning" : "info",
    data: {
      task_id: taskId,
      ...context,
    },
  });
}

/**
 * Add breadcrumb for authentication events
 * @param event - Auth event (login, logout, signup)
 * @param context - Additional context data
 */
export function addAuthEvent(
  event: "login" | "logout" | "signup" | "error",
  context?: BreadcrumbContext,
) {
  Sentry.addBreadcrumb({
    message: `Auth event: ${event}`,
    category: "auth",
    level: event === "error" ? "warning" : "info",
    data: context,
  });
}

/**
 * Add breadcrumb for form submissions
 * @param formName - Name of the form
 * @param status - Status of submission
 * @param context - Additional context data
 */
export function addFormSubmission(
  formName: string,
  status: "started" | "success" | "error",
  context?: BreadcrumbContext,
) {
  Sentry.addBreadcrumb({
    message: `Form submission: ${formName}`,
    category: "form",
    level: status === "error" ? "warning" : "info",
    data: {
      status,
      ...context,
    },
  });
}

/**
 * Add breadcrumb for navigation
 * @param from - Source path
 * @param to - Destination path
 */
export function addNavigation(from: string, to: string) {
  Sentry.addBreadcrumb({
    message: `Navigation: ${from} → ${to}`,
    category: "navigation",
    level: "info",
  });
}

/**
 * Add breadcrumb for scan operations
 * @param operation - Operation type (create, start, cancel, etc.)
 * @param scanId - Scan identifier
 * @param context - Additional context data
 */
export function addScanOperation(
  operation: "create" | "start" | "cancel" | "pause" | "resume",
  scanId?: string,
  context?: BreadcrumbContext,
) {
  Sentry.addBreadcrumb({
    message: `Scan ${operation}${scanId ? `: ${scanId}` : ""}`,
    category: "scan",
    level: "info",
    data: {
      scan_id: scanId,
      ...context,
    },
  });
}

/**
 * Add breadcrumb for data mutations
 * @param entity - Entity type (provider, scan, role, etc.)
 * @param action - Action type (create, update, delete)
 * @param entityId - Entity identifier
 * @param context - Additional context data
 */
export function addDataMutation(
  entity: string,
  action: "create" | "update" | "delete",
  entityId?: string,
  context?: BreadcrumbContext,
) {
  Sentry.addBreadcrumb({
    message: `Data mutation: ${action} ${entity}${entityId ? ` (${entityId})` : ""}`,
    category: "data",
    level: "info",
    data: {
      entity,
      action,
      entity_id: entityId,
      ...context,
    },
  });
}
