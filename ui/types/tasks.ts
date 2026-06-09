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
