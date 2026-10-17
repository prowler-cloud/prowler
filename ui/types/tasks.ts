/**
 * Generic settle outcome for a polled async task: it succeeded, it failed, or the
 * wait was exhausted with the task still running. `CONNECTION_CHECK_STATUS` in
 * `types/providers.ts` is a connection-specific alias of this same shape, kept as
 * its own export so a caller that only cares about a connection result does not
 * have to name a generic task type to use it.
 */
export const TASK_OUTCOME = {
  SUCCESS: "success",
  FAILED: "failed",
  PENDING: "pending",
} as const;

export type TaskOutcome = (typeof TASK_OUTCOME)[keyof typeof TASK_OUTCOME];

export type TaskState =
  | "available"
  | "scheduled"
  | "executing"
  | "completed"
  | "failed"
  | "cancelled";

export interface TaskAttributes<R = unknown> {
  state?: TaskState;
  result?: R;
}

export interface TaskData<R = unknown> {
  attributes?: TaskAttributes<R>;
}

export type GetTaskResponse<R = unknown> =
  | { data: TaskData<R> }
  | { error: string };

export interface PollOptions {
  maxAttempts?: number;
  delayMs?: number;
}

export type PollSettledResult<R = unknown> =
  | {
      ok: true;
      state: TaskState;
      task: TaskData<R>;
      result: R | undefined;
    }
  | {
      ok: false;
      error: string;
      state?: TaskState;
      task?: TaskData<R>;
      result?: R;
    };

export interface TaskDetails {
  attributes: {
    state: string;
    completed_at: string;
    result: {
      exc_type?: string;
      exc_message?: string[];
      exc_module?: string;
    };
    task_args: {
      scan_id: string;
      provider_id: string;
      checks_to_execute: string[];
    };
  };
}
