import type { SentInvitation } from "@/types/onboarding-invite";

const readString = (value: unknown): string | null =>
  typeof value === "string" && value.length > 0 ? value : null;

/**
 * The created record out of `sendInvite`'s JSON:API response. Null for every
 * failure shape: `undefined` (a 5xx makes the action resolve without a value),
 * `{ errors }`, a bare `{ error }`, or a record missing what the link needs.
 */
export function toSentInvitation(response: unknown): SentInvitation | null {
  if (!response || typeof response !== "object") return null;
  const { data } = response as { data?: unknown };
  if (!data || typeof data !== "object") return null;
  const { id, attributes } = data as { id?: unknown; attributes?: unknown };
  const fields =
    attributes && typeof attributes === "object"
      ? (attributes as Record<string, unknown>)
      : {};
  const invitationId = readString(id);
  const email = readString(fields.email);
  const token = readString(fields.token);
  if (!invitationId || !email || !token) return null;
  return { id: invitationId, email, token };
}
