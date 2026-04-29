import { z } from "zod";

export const CUSTOM_ATTACK_PATH_QUERY_MAX_LENGTH = 10000;
export const CUSTOM_ATTACK_PATH_QUERY_READ_ONLY_ERROR_MESSAGE =
  "Only read-only queries are allowed";
const CUSTOM_ATTACK_PATH_QUERY_STRING_LITERALS =
  /'(?:[^'\\]|\\.)*'|"(?:[^"\\]|\\.)*"/g;
const CUSTOM_ATTACK_PATH_BLOCKED_PATTERNS = [
  /\bCREATE\b/i,
  /\bMERGE\b/i,
  /\bSET\b/i,
  /\bREMOVE\b/i,
  /\bDELETE\b/i,
  /\bDETACH\s+DELETE\b/i,
  /\bDROP\b/i,
  /\bLOAD\s+CSV\b/i,
  /\bapoc\.(?:load|import|export|cypher|systemdb|config|periodic|do|trigger|custom)\b/i,
] as const;

const containsBlockedOperation = (query: string): boolean => {
  const normalizedQuery = query.replace(
    CUSTOM_ATTACK_PATH_QUERY_STRING_LITERALS,
    "",
  );

  return CUSTOM_ATTACK_PATH_BLOCKED_PATTERNS.some((pattern) =>
    pattern.test(normalizedQuery),
  );
};

export const customAttackPathQuerySchema = z
  .string()
  .max(
    CUSTOM_ATTACK_PATH_QUERY_MAX_LENGTH,
    `Custom query must be ${CUSTOM_ATTACK_PATH_QUERY_MAX_LENGTH} characters or fewer`,
  )
  .refine((value) => value.trim().length > 0, {
    message: "Custom query cannot be empty",
  })
  .refine((value) => !containsBlockedOperation(value), {
    message: CUSTOM_ATTACK_PATH_QUERY_READ_ONLY_ERROR_MESSAGE,
  });
