export const LIGHTHOUSE_V2_SESSIONS_CHANGED_EVENT =
  "lighthouse-v2:sessions-changed";

export function notifyLighthouseV2SessionsChanged() {
  if (typeof window === "undefined") return;
  window.dispatchEvent(new Event(LIGHTHOUSE_V2_SESSIONS_CHANGED_EVENT));
}
