"use server";

import { apiBaseUrl, getAuthHeaders } from "@/lib";
import { runWithConcurrencyLimit } from "@/lib/concurrency";
import { handleApiError, handleApiResponse } from "@/lib/server-actions-helper";

export const getTask = async (taskId: string) => {
  const headers = await getAuthHeaders({ contentType: false });

  const url = new URL(`${apiBaseUrl}/tasks/${taskId}`);

  try {
    const response = await fetch(url.toString(), {
      headers,
    });

    return handleApiResponse(response);
  } catch (error) {
    return handleApiError(error);
  }
};

/** Task reads in flight at once. */
const TASK_READ_CONCURRENCY_LIMIT = 10;

/**
 * Reads several tasks in one call, keyed by task id, each entry shaped like
 * {@link getTask}'s.
 *
 * Client-invoked server actions run one at a time through Next's action queue,
 * so polling N tasks with `getTask` costs N sequential round trips per round.
 * The reads are still one request per task — `TaskFilter` exposes no id filter —
 * but they overlap here instead of queueing on the client.
 */
export const getTasksByIds = async (
  taskIds: string[],
): Promise<Record<string, unknown>> => {
  const uniqueIds = Array.from(new Set(taskIds.filter(Boolean)));
  if (uniqueIds.length === 0) {
    return {};
  }

  const headers = await getAuthHeaders({ contentType: false });
  const snapshots: Record<string, unknown> = {};

  await runWithConcurrencyLimit(
    uniqueIds,
    TASK_READ_CONCURRENCY_LIMIT,
    async (taskId) => {
      const url = new URL(`${apiBaseUrl}/tasks/${taskId}`);

      try {
        const response = await fetch(url.toString(), { headers });
        snapshots[taskId] = await handleApiResponse(response);
      } catch (error) {
        snapshots[taskId] = handleApiError(error);
      }
    },
  );

  return snapshots;
};
