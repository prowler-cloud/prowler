"use server";

import { auth } from "@/auth.config";
import { getErrorMessage, parseStringify } from "@/lib";

export const getTask = async (taskId: string) => {
  const session = await auth();

  const keyServer = process.env.API_BASE_URL;
  const url = new URL(`${keyServer}/tasks/${taskId}`);

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
