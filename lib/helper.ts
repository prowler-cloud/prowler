import { getTask } from "@/actions/task";
import { MetaDataProps } from "@/types";

export async function checkTaskStatus(
  taskId: string,
): Promise<{ completed: boolean; error?: string }> {
  const MAX_RETRIES = 20; // Define the maximum number of attempts before stopping the polling
  const RETRY_DELAY = 1000; // Delay time between each poll (in milliseconds)

  for (let attempt = 0; attempt < MAX_RETRIES; attempt++) {
    const task = await getTask(taskId);

    if (task.error) {
      // eslint-disable-next-line no-console
      console.error(`Error retrieving task: ${task.error}`);
      return { completed: false, error: task.error };
    }

    const state = task.data.attributes.state;

    switch (state) {
      case "completed":
        return { completed: true };
      case "failed":
        return { completed: false, error: task.data.attributes.result.error };
      case "available":
      case "scheduled":
      case "executing":
        // Continue waiting if the task is still in progress
        await new Promise((resolve) => setTimeout(resolve, RETRY_DELAY));
        break;
      default:
        console.warn(`Unexpected task state: ${state}`);
        return { completed: false, error: "Unexpected task state" };
    }
  }

  return { completed: false, error: "Max retries exceeded" };
}

export const wait = (ms: number) =>
  new Promise((resolve) => setTimeout(resolve, ms));

// Helper function to create dictionaries by type
export function createDict(type: string, data: any) {
  const includedField = data?.included?.filter(
    (item: { type: string }) => item.type === type,
  );

  if (!includedField || includedField.length === 0) {
    return {};
  }

  return Object.fromEntries(
    includedField.map((item: { id: string }) => [item.id, item]),
  );
}

export const parseStringify = (value: any) => JSON.parse(JSON.stringify(value));

export const convertFileToUrl = (file: File) => URL.createObjectURL(file);

export const getPaginationInfo = (metadata: MetaDataProps) => {
  const currentPage = metadata?.pagination.page ?? "1";
  const totalPages = metadata?.pagination.pages;
  const totalEntries = metadata?.pagination.count;

  return { currentPage, totalPages, totalEntries };
};

export function encryptKey(passkey: string) {
  return btoa(passkey);
}

export function decryptKey(passkey: string) {
  return atob(passkey);
}

export const getErrorMessage = async (error: unknown): Promise<string> => {
  let message: string;

  if (error instanceof Error) {
    message = error.message;
  } else if (error && typeof error === "object" && "message" in error) {
    message = String(error.message);
  } else if (typeof error === "string") {
    message = error;
  } else {
    message = "Oops! Something went wrong.";
  }
  return message;
};
