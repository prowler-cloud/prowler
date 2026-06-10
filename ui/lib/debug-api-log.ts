/* eslint-disable no-console */
// TEMPORARY debug logging for server-action requests. TODO: remove before merging.

export function logApiRequest(method: string, url: string, body?: unknown) {
  console.log(
    `[api-debug] -> ${method} ${url}${body !== undefined ? ` body=${JSON.stringify(body)}` : ""}`,
  );
}

// clone() so the body stream stays readable for handleApiResponse.
export async function logApiResponse(
  method: string,
  url: string,
  response: Response,
) {
  const body = await response
    .clone()
    .text()
    .catch(() => "<unreadable body>");
  console.log(
    `[api-debug] <- ${method} ${url} status=${response.status} body=${body}`,
  );
}

export function logApiError(method: string, url: string, error: unknown) {
  const detail =
    error instanceof Error
      ? { name: error.name, message: error.message }
      : error;
  console.log(
    `[api-debug] !! ${method} ${url} error=${JSON.stringify(detail)}`,
  );
}
