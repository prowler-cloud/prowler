"use server";

import { auth } from "@/auth.config";
import { apiBaseUrl, getErrorMessage, parseStringify } from "@/lib";

export const getTask = async (taskId: string) => {
  const session = await auth();

  const url = new URL(`${apiBaseUrl}/tasks/${taskId}`);

  try {
    const response = await fetch(url.toString(), {
      headers: {
        Accept: "application/vnd.api+json",
        Authorization: `Bearer ${session?.accessToken}`,
      },
    });
    const data = await response.json();
    return parseStringify(data);
  } catch (error) {
    return { error: getErrorMessage(error) };
  }
};
