import type { RealtimeStatusPayload } from "@/types/realtime";

/**
 * The statement as the API returned it. Keys are already sorted by the API, and
 * the hash covers every field but `sha256`, so nothing is added or reordered
 * here: what a reader copies is what the stamp vouches for.
 */
export const statementToJson = (statement: RealtimeStatusPayload): string =>
  JSON.stringify(statement, null, 2);

export const statementFilename = (statement: RealtimeStatusPayload): string =>
  `prowler-realtime-status-${statement.generated_on}.json`;
