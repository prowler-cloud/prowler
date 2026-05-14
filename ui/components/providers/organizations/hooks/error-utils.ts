interface ErrorResult {
  error?: string;
  errors?: Array<{ detail?: string }>;
}

export function extractErrorMessage(
  response: unknown,
  fallback: string,
): string {
  if (!response || typeof response !== "object") {
    return fallback;
  }

  const responseRecord = response as ErrorResult;
  const detailedError = responseRecord.errors?.[0]?.detail;

  return detailedError || responseRecord.error || fallback;
}
