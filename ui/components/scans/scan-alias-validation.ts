import { z } from "zod";

export const SCAN_ALIAS_MIN_LENGTH = 3;
export const SCAN_ALIAS_MAX_LENGTH = 100;

export const scanAliasSchema = z
  .string()
  .max(
    SCAN_ALIAS_MAX_LENGTH,
    `Alias must not exceed ${SCAN_ALIAS_MAX_LENGTH} characters.`,
  )
  .refine(
    (value) =>
      value.trim().length === 0 || value.trim().length >= SCAN_ALIAS_MIN_LENGTH,
    `Alias must be empty or have at least ${SCAN_ALIAS_MIN_LENGTH} characters.`,
  );
