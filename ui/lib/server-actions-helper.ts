import { revalidatePath } from "next/cache";

import { getErrorMessage, parseStringify } from "./helper";

// Helper function to handle API responses consistently
export const handleApiResponse = async (
  response: Response,
  pathToRevalidate?: string,
  parse = true,
) => {
  if (!response.ok) {
    // Read error body safely; prefer JSON, fallback to plain text
    const rawErrorText = await response.text().catch(() => "");
    let errorData: any = null;
    try {
      errorData = rawErrorText ? JSON.parse(rawErrorText) : null;
    } catch {
      errorData = null;
    }

    const errorsArray = Array.isArray(errorData?.errors)
      ? (errorData.errors as any[])
      : undefined;
    const errorDetail =
      errorsArray?.[0]?.detail ||
      errorData?.error ||
      errorData?.message ||
      (rawErrorText && rawErrorText.trim()) ||
      response.statusText ||
      "Oops! Something went wrong.";

    //5XX errors
    if (response.status >= 500) {
      throw new Error(
        errorDetail ||
          `Server error (${response.status}): The server encountered an error. Please try again later.`,
      );
    }

    return errorsArray
      ? { error: errorDetail, errors: errorsArray, status: response.status }
      : ({ error: errorDetail, status: response.status } as any);
  }

  // Handle empty or no-content responses gracefully (e.g., 204, empty body)
  if (response.status === 204) {
    if (pathToRevalidate && pathToRevalidate !== "") {
      revalidatePath(pathToRevalidate);
    }
    return { success: true, status: response.status } as any;
  }

  // Read raw text to determine if there's a body to parse
  const rawText = await response.text();
  const hasBody = rawText && rawText.trim().length > 0;

  if (!hasBody) {
    if (pathToRevalidate && pathToRevalidate !== "") {
      revalidatePath(pathToRevalidate);
    }
    return { success: true, status: response.status } as any;
  }

  let data: any;
  try {
    data = JSON.parse(rawText);
  } catch (e) {
    // If body isn't valid JSON, return as text payload
    data = { data: rawText };
  }

  if (pathToRevalidate && pathToRevalidate !== "") {
    revalidatePath(pathToRevalidate);
  }

  return parse ? parseStringify(data) : data;
};

// Helper function to handle API errors consistently
export const handleApiError = (error: unknown): { error: string } => {
  console.error(error);
  return {
    error: getErrorMessage(error),
  };
};
