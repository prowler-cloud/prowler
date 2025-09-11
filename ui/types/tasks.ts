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
