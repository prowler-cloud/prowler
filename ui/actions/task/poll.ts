"use server";

import { getTask } from "@/actions/task/tasks";

export type TaskState = string;

export interface PollOptions {
  maxAttempts?: number;
  delayMs?: number;
}

export type PollSettledResult =
  | {
      ok: true;
      state: TaskState;
      task: any;
      result: any;
    }
  | {
      ok: false;
      error: string;
      state?: TaskState;
      task?: any;
      result?: any;
    };

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

export async function pollTaskUntilSettled(
  taskId: string,
  { maxAttempts = 10, delayMs = 2000 }: PollOptions = {},
): Promise<PollSettledResult> {
  let attempts = 0;
  while (attempts < maxAttempts) {
    const resp = await getTask(taskId);
    if (resp?.error) {
      return { ok: false, error: resp.error };
    }
    const task = resp?.data;
    const state: TaskState | undefined = task?.attributes?.state;
    const result = task?.attributes?.result;

    if (!state) {
      return { ok: false, error: "Task state unavailable", task };
    }

    if (state !== "executing" && state !== "available") {
      return { ok: true, state, task, result };
    }

    attempts++;
    await sleep(delayMs);
  }
  return { ok: false, error: "Task timeout" };
}
