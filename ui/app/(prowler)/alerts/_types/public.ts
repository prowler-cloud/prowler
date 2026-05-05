// Public confirm / unsubscribe contract for Alerts public pages.
// NOT FOR THE MVP: keep only if public recipient consent links are required.
// Mirrors the API's ``{state, message}`` JSON contract from the public
// alert recipient endpoints. ``network_error`` is UI-side only: the
// fetch wrapper folds connection failures into the same shape so the
// caller has a single switch to render.
export const ALERT_PUBLIC_STATES = {
  CONFIRMED: "confirmed",
  ALREADY_CONFIRMED: "already_confirmed",
  CANNOT_CONFIRM: "cannot_confirm",
  UNSUBSCRIBED: "unsubscribed",
  ALREADY_UNSUBSCRIBED: "already_unsubscribed",
  MISSING_TOKEN: "missing_token",
  INVALID_TOKEN: "invalid_token",
  SUPERSEDED: "superseded",
  NOT_FOUND: "not_found",
  NETWORK_ERROR: "network_error",
} as const;
export type AlertPublicState =
  (typeof ALERT_PUBLIC_STATES)[keyof typeof ALERT_PUBLIC_STATES];

export interface AlertPublicResponse {
  state: AlertPublicState;
  message: string;
}
