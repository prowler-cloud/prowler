"use server";

import { getTask } from "@/actions/task/tasks";
import type {
  GetTaskResponse,
  PollOptions,
  PollSettledResult,
  TaskState,
} from "@/types/tasks";

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

export async function pollTaskUntilSettled<R = unknown>(
  taskId: string,
  { maxAttempts = 10, delayMs = 2000 }: PollOptions = {},
): Promise<PollSettledResult<R>> {
  let attempts = 0;
  while (attempts < maxAttempts) {
    const resp = (await getTask(taskId)) as GetTaskResponse<R>;
    if ("error" in resp) {
      return { ok: false, error: resp.error };
    }
    const task = resp.data;
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
