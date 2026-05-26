/**
 * Normalizes a resource `metadata` value into a plain object.
 *
 * The API stores resource metadata as a `TextField`, so it can arrive as a
 * JSON string, an already-parsed object, or be empty. Returns `null` when the
 * value is missing or not a JSON object so callers can render an empty state.
 */
export const parseMetadata = (
  metadata: Record<string, unknown> | string | null | undefined,
): Record<string, unknown> | null => {
  if (!metadata) return null;

  if (typeof metadata === "string") {
    try {
      const parsed = JSON.parse(metadata);
      return typeof parsed === "object" &&
        parsed !== null &&
        !Array.isArray(parsed)
        ? parsed
        : null;
    } catch {
      return null;
    }
  }

  // After the !metadata check above, metadata can only be a non-null object
  // here (null was filtered, string was handled). Arrays are excluded too so
  // the Record<string, unknown> return type stays honest.
  if (typeof metadata === "object" && !Array.isArray(metadata)) {
    return metadata as Record<string, unknown>;
  }

  return null;
};
