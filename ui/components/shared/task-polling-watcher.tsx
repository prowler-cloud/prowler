"use client";

import {
  CROSS_PROVIDER_PDF_TASK_KIND,
  crossProviderPdfHandler,
} from "@/app/(prowler)/compliance/_lib/cross-provider-pdf";
import { useMountEffect } from "@/hooks/use-mount-effect";
import {
  registerTaskKindHandler,
  resumePendingTasks,
} from "@/store/task-watcher/store";

// Kind registrations happen at module scope, before any task can settle in
// this tab. Adding a new watched task kind (integration tests, scan exports,
// …) is one line here plus a handler next to the feature that owns it.
registerTaskKindHandler(CROSS_PROVIDER_PDF_TASK_KIND, crossProviderPdfHandler);

/**
 * Mounted once in the app layout (next to `Toaster`): resumes polling any
 * backend task persisted as pending by `@/store/task-watcher`, so completion
 * toasts survive a hard reload. In-session tracking needs no component at
 * all — `trackAndPollTask` runs its loop at module scope from the
 * dispatching click handler.
 */
export const TaskPollingWatcher = () => {
  useMountEffect(() => {
    resumePendingTasks();
  });

  return null;
};
