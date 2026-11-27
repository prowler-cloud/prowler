import { create } from "zustand";
import { persist } from "zustand/middleware";

import { pollTaskUntilSettled } from "@/actions/task/poll";

// Generic background-task watcher: any feature that dispatches a backend
// task (report generation, integration tests, exports…) can track it here
// under a `kind` and get its completion handler fired even after the user
// navigates away. State persists to localStorage so a hard reload resumes
// in-flight tasks via `resumePendingTasks` (mounted once in the app layout
// through `TaskPollingWatcher`).

export const TASK_WATCHER_STATUS = {
  PENDING: "pending",
  READY: "ready",
  ERROR: "error",
} as const;

export type TaskWatcherStatus =
  (typeof TASK_WATCHER_STATUS)[keyof typeof TASK_WATCHER_STATUS];

export interface WatchedTask {
  taskId: string;
  kind: string;
  status: TaskWatcherStatus;
  /** Small serializable context the kind handler needs (ids, filenames…).
   *  Never store sensitive values: this persists to localStorage. */
  meta: Record<string, string>;
  startedAt: number;
  error?: string;
  /** Serializable task result. Persisted so another tab or a reload can
   *  finish feature-specific handling without polling the task again. */
  result?: unknown;
}

export interface TaskKindHandler {
  onReady: (task: WatchedTask) => void;
  onError: (task: WatchedTask) => void;
}

export interface TaskTrackingResult<R = unknown> {
  status: TaskWatcherStatus;
  error?: string;
  result?: R;
}

export interface TrackAndPollTaskInput {
  taskId: string;
  kind: string;
  meta: Record<string, string>;
  /** Let the awaiting caller aggregate notifications. If this tab reloads,
   *  the persisted task resumes with its registered handler as usual. */
  notifyHandler?: boolean;
}

interface TaskWatcherState {
  tasks: Record<string, WatchedTask>;
  upsertTask: (task: WatchedTask) => void;
  resolveTask: (
    taskId: string,
    status: TaskWatcherStatus,
    error?: string,
    result?: unknown,
  ) => void;
  dismissTask: (taskId: string) => void;
}

/** Tasks pending longer than this are considered lost on resume. */
const STALE_TASK_MS = 30 * 60 * 1000;
/** Poll rounds per task; each server round is itself 10 × 2s. */
const MAX_POLL_ROUNDS = 15;

const handlers = new Map<string, TaskKindHandler>();

/** Registers the completion handler for a task kind. Kinds are registered at
 *  module scope by `task-kind-registrations`, so they exist before any task
 *  can settle. */
export const registerTaskKindHandler = (
  kind: string,
  handler: TaskKindHandler,
): void => {
  handlers.set(kind, handler);
};

export const useTaskWatcherStore = create<TaskWatcherState>()(
  persist(
    (set) => ({
      tasks: {},
      upsertTask: (task) =>
        set((state) => ({ tasks: { ...state.tasks, [task.taskId]: task } })),
      resolveTask: (taskId, status, error, result) =>
        set((state) => {
          const task = state.tasks[taskId];
          if (!task) return state;
          return {
            tasks: {
              ...state.tasks,
              [taskId]: { ...task, status, error, result },
            },
          };
        }),
      dismissTask: (taskId) =>
        set((state) => {
          const { [taskId]: _dismissed, ...rest } = state.tasks;
          return { tasks: rest };
        }),
    }),
    {
      name: "task-watcher",
      partialize: (state) => ({ tasks: state.tasks }),
    },
  ),
);

// In-memory only: poll loops alive in THIS tab. Never persisted, so a reload
// naturally re-enters through resumePendingTasks without double-polling.
const activePolls = new Map<string, Promise<TaskTrackingResult<unknown>>>();
const suppressedHandlers = new Set<string>();

// Navigation aborts outstanding Server Action requests. That is not a backend
// task failure: keep its persisted identity for the next document to resume.
let pageSuspended = false;
let pageHidden = false;
let navigationGeneration = 0;
let pageRecoveryTimer: ReturnType<typeof setTimeout> | undefined;
const pageRecoveryWaiters = new Set<(visible: boolean) => void>();

const resolvePageRecovery = (visible: boolean) => {
  pageRecoveryWaiters.forEach((resolve) => resolve(visible));
  pageRecoveryWaiters.clear();
};

const resumeVisiblePage = () => {
  clearTimeout(pageRecoveryTimer);
  // Downloads and cancelled navigation emit beforeunload without pagehide.
  // Let pagehide confirm navigation before retrying in the surviving document.
  pageRecoveryTimer = setTimeout(() => {
    pageRecoveryTimer = undefined;
    if (pageHidden) return;
    pageSuspended = false;
    resolvePageRecovery(true);
    void resumePendingTaskPolling();
  }, 0);
};

const waitForVisiblePage = (): Promise<boolean> => {
  if (pageHidden) return Promise.resolve(false);
  return new Promise((resolve) => {
    pageRecoveryWaiters.add(resolve);
    resumeVisiblePage();
  });
};

if (typeof window !== "undefined") {
  // Browsers can abort a Server Action before pagehide is dispatched.
  // Mark the navigation at its start so that abort cannot discard the task.
  window.addEventListener("beforeunload", () => {
    navigationGeneration++;
    pageSuspended = true;
    resumeVisiblePage();
  });
  window.addEventListener("pagehide", () => {
    navigationGeneration++;
    clearTimeout(pageRecoveryTimer);
    pageHidden = true;
    pageSuspended = true;
    resolvePageRecovery(false);
  });
  window.addEventListener("pageshow", (event) => {
    clearTimeout(pageRecoveryTimer);
    pageHidden = false;
    pageSuspended = false;
    resolvePageRecovery(true);
    if (event.persisted) void resumePendingTaskPolling();
  });
}

const settleTask = (
  taskId: string,
  status: TaskWatcherStatus,
  error?: string,
  result?: unknown,
): TaskTrackingResult => {
  if (pageSuspended) return { status: TASK_WATCHER_STATUS.PENDING };
  const store = useTaskWatcherStore.getState();
  const currentTask = store.tasks[taskId];
  if (!currentTask || currentTask.status !== TASK_WATCHER_STATUS.PENDING) {
    return {
      status: currentTask?.status ?? TASK_WATCHER_STATUS.ERROR,
      ...(currentTask?.error ? { error: currentTask.error } : {}),
      ...(currentTask?.result !== undefined
        ? { result: currentTask.result }
        : {}),
    };
  }

  store.resolveTask(taskId, status, error, result);
  const task = useTaskWatcherStore.getState().tasks[taskId];
  if (!task) {
    return { status: TASK_WATCHER_STATUS.ERROR, error: "Task unavailable." };
  }

  const handler = handlers.get(task.kind);
  if (handler && !suppressedHandlers.has(taskId)) {
    if (status === TASK_WATCHER_STATUS.READY) handler.onReady(task);
    else handler.onError(task);
  }

  // Error details have no durable consumer after the handler surfaces them.
  // Ready tasks stay available so feature UI can expose their result.
  if (status === TASK_WATCHER_STATUS.ERROR) {
    store.dismissTask(taskId);
  }

  return {
    status,
    ...(error ? { error } : {}),
    ...(result !== undefined ? { result } : {}),
  };
};

const runPollLoop = async <R>(
  taskId: string,
): Promise<TaskTrackingResult<R>> => {
  for (let round = 0; round < MAX_POLL_ROUNDS; round++) {
    const result = await pollTaskUntilSettled<R>(taskId);

    if (result.ok) {
      if (result.state === "completed") {
        return settleTask(
          taskId,
          TASK_WATCHER_STATUS.READY,
          undefined,
          result.result,
        ) as TaskTrackingResult<R>;
      } else {
        return settleTask(
          taskId,
          TASK_WATCHER_STATUS.ERROR,
          `Task ended in state "${result.state}".`,
          result.result,
        ) as TaskTrackingResult<R>;
      }
    }

    // "Task timeout" just means this server round expired while the task
    // is still running — keep polling. Real errors settle immediately.
    if (result.error !== "Task timeout") {
      return settleTask(
        taskId,
        TASK_WATCHER_STATUS.ERROR,
        result.error,
        result.result,
      ) as TaskTrackingResult<R>;
    }
  }

  return settleTask(
    taskId,
    TASK_WATCHER_STATUS.ERROR,
    "The task is taking too long. Try again later.",
  ) as TaskTrackingResult<R>;
};

const pollUntilDone = <R>(taskId: string): Promise<TaskTrackingResult<R>> => {
  const existingPoll = activePolls.get(taskId);
  if (existingPoll) return existingPoll as Promise<TaskTrackingResult<R>>;

  const pollPromise = (async (): Promise<TaskTrackingResult<R>> => {
    try {
      const runIfPending = async (): Promise<TaskTrackingResult<R>> => {
        // A different tab may have completed the task while this one waited for
        // the cross-tab lock. Refresh persisted state before polling or notifying.
        await useTaskWatcherStore.persist.rehydrate();
        const task = useTaskWatcherStore.getState().tasks[taskId];
        if (task?.status !== TASK_WATCHER_STATUS.PENDING) {
          return {
            status: task?.status ?? TASK_WATCHER_STATUS.ERROR,
            ...(task?.error ? { error: task.error } : {}),
            ...(task?.result !== undefined ? { result: task.result as R } : {}),
          };
        }
        return runPollLoop<R>(taskId);
      };

      for (;;) {
        const pollNavigationGeneration = navigationGeneration;
        try {
          const result =
            typeof navigator !== "undefined" && navigator.locks
              ? await navigator.locks.request(
                  `task-watcher:${taskId}`,
                  runIfPending,
                )
              : await runIfPending();
          if (result.status !== TASK_WATCHER_STATUS.PENDING) return result;
        } catch {
          if (
            !pageSuspended &&
            navigationGeneration === pollNavigationGeneration
          ) {
            return settleTask(
              taskId,
              TASK_WATCHER_STATUS.ERROR,
              "Tracking the task failed unexpectedly. Try again later.",
            ) as TaskTrackingResult<R>;
          }
        }

        // Downloads and cancelled navigation keep the original caller alive.
        // Retry within its promise so it retains notification ownership and
        // receives a terminal result. Only a hidden document hands off to resume.
        if (!(await waitForVisiblePage())) {
          return { status: TASK_WATCHER_STATUS.PENDING };
        }
      }
    } finally {
      activePolls.delete(taskId);
    }
  })();

  activePolls.set(taskId, pollPromise);
  return pollPromise;
};

/** Track a freshly dispatched backend task and poll it to completion. The
 *  poll loop lives at module scope (fired from the click handler), so it
 *  survives client-side navigation without any effect subscriptions. */
export const trackAndPollTask = async <R = unknown>({
  taskId,
  kind,
  meta,
  notifyHandler = true,
}: TrackAndPollTaskInput): Promise<TaskTrackingResult<R>> => {
  if (!notifyHandler) suppressedHandlers.add(taskId);

  const existing = useTaskWatcherStore.getState().tasks[taskId];
  try {
    if (existing?.status === TASK_WATCHER_STATUS.PENDING) {
      return await pollUntilDone<R>(taskId);
    }

    const store = useTaskWatcherStore.getState();
    Object.values(store.tasks)
      .filter(
        (task) =>
          task.kind === kind && task.status !== TASK_WATCHER_STATUS.PENDING,
      )
      .forEach((task) => store.dismissTask(task.taskId));

    store.upsertTask({
      taskId,
      kind,
      status: TASK_WATCHER_STATUS.PENDING,
      meta,
      startedAt: Date.now(),
    });

    return await pollUntilDone<R>(taskId);
  } finally {
    suppressedHandlers.delete(taskId);
  }
};

/** Resume polling every persisted pending task after a hard reload; tasks
 *  pending longer than the staleness ceiling are settled as errors without
 *  hitting the API. Called once on app mount by `TaskPollingWatcher`. */
export const resumePendingTasks = async (): Promise<void> => {
  const store = useTaskWatcherStore.getState();
  const persistedTasks = Object.values(store.tasks);

  // Settled entries already surfaced in the previous browser session. The
  // server-rendered feature UI resolves durable results again on reload, so
  // keeping these records would only grow localStorage forever.
  persistedTasks
    .filter((task) => task.status !== TASK_WATCHER_STATUS.PENDING)
    .forEach((task) => store.dismissTask(task.taskId));

  await resumePendingTaskPolling();
};

async function resumePendingTaskPolling(): Promise<void> {
  const pending = Object.values(useTaskWatcherStore.getState().tasks).filter(
    (task) => task.status === TASK_WATCHER_STATUS.PENDING,
  );
  await Promise.all(
    pending.map((task) => {
      if (Date.now() - task.startedAt > STALE_TASK_MS) {
        settleTask(
          task.taskId,
          TASK_WATCHER_STATUS.ERROR,
          "The task expired before it could be tracked to completion.",
        );
        return Promise.resolve();
      }
      return pollUntilDone(task.taskId);
    }),
  );
}
