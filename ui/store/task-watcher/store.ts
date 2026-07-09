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
}

export interface TaskKindHandler {
  onReady: (task: WatchedTask) => void;
  onError: (task: WatchedTask) => void;
}

interface TaskWatcherState {
  tasks: Record<string, WatchedTask>;
  upsertTask: (task: WatchedTask) => void;
  resolveTask: (
    taskId: string,
    status: TaskWatcherStatus,
    error?: string,
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
      resolveTask: (taskId, status, error) =>
        set((state) => {
          const task = state.tasks[taskId];
          if (!task) return state;
          return {
            tasks: { ...state.tasks, [taskId]: { ...task, status, error } },
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
const activePolls = new Set<string>();

const settleTask = (
  taskId: string,
  status: TaskWatcherStatus,
  error?: string,
) => {
  const store = useTaskWatcherStore.getState();
  store.resolveTask(taskId, status, error);
  const task = useTaskWatcherStore.getState().tasks[taskId];
  if (!task) return;

  const handler = handlers.get(task.kind);
  if (!handler) return;
  if (status === TASK_WATCHER_STATUS.READY) handler.onReady(task);
  else handler.onError(task);
};

const pollUntilDone = async (taskId: string): Promise<void> => {
  if (activePolls.has(taskId)) return;
  activePolls.add(taskId);

  try {
    for (let round = 0; round < MAX_POLL_ROUNDS; round++) {
      const result = await pollTaskUntilSettled(taskId);

      if (result.ok) {
        if (result.state === "completed") {
          settleTask(taskId, TASK_WATCHER_STATUS.READY);
        } else {
          settleTask(
            taskId,
            TASK_WATCHER_STATUS.ERROR,
            `Task ended in state "${result.state}".`,
          );
        }
        return;
      }

      // "Task timeout" just means this server round expired while the task
      // is still running — keep polling. Real errors settle immediately.
      if (result.error !== "Task timeout") {
        settleTask(taskId, TASK_WATCHER_STATUS.ERROR, result.error);
        return;
      }
    }

    settleTask(
      taskId,
      TASK_WATCHER_STATUS.ERROR,
      "The task is taking too long. Try again later.",
    );
  } catch {
    // A thrown poll (e.g. the server-action RPC failing on a network drop)
    // must still settle the task, or it stays PENDING in the persisted
    // store and blocks the UI until the staleness ceiling.
    settleTask(
      taskId,
      TASK_WATCHER_STATUS.ERROR,
      "Tracking the task failed unexpectedly. Try again later.",
    );
  } finally {
    activePolls.delete(taskId);
  }
};

/** Track a freshly dispatched backend task and poll it to completion. The
 *  poll loop lives at module scope (fired from the click handler), so it
 *  survives client-side navigation without any effect subscriptions. */
export const trackAndPollTask = async ({
  taskId,
  kind,
  meta,
}: {
  taskId: string;
  kind: string;
  meta: Record<string, string>;
}): Promise<void> => {
  const existing = useTaskWatcherStore.getState().tasks[taskId];
  if (existing?.status === TASK_WATCHER_STATUS.PENDING) {
    return pollUntilDone(taskId);
  }

  useTaskWatcherStore.getState().upsertTask({
    taskId,
    kind,
    status: TASK_WATCHER_STATUS.PENDING,
    meta,
    startedAt: Date.now(),
  });

  return pollUntilDone(taskId);
};

/** Resume polling every persisted pending task after a hard reload; tasks
 *  pending longer than the staleness ceiling are settled as errors without
 *  hitting the API. Called once on app mount by `TaskPollingWatcher`. */
export const resumePendingTasks = async (): Promise<void> => {
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
};
