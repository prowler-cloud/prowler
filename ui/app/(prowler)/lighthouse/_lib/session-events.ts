export const LIGHTHOUSE_V2_SESSIONS_CHANGED_EVENT =
  "lighthouse-v2:sessions-changed";

export function notifyLighthouseV2SessionsChanged() {
  if (typeof window === "undefined") return;
  window.dispatchEvent(new Event(LIGHTHOUSE_V2_SESSIONS_CHANGED_EVENT));
}

export const LIGHTHOUSE_V2_SESSION_ARCHIVED_EVENT =
  "lighthouse-v2:session-archived";

// Carries the archived session id so the chat page can reset itself when its
// open session is archived. Needed because sessions created live set their URL
// via replaceState, so the sidebar can't spot them through useSearchParams.
export function notifyLighthouseV2SessionArchived(sessionId: string) {
  if (typeof window === "undefined") return;
  window.dispatchEvent(
    new CustomEvent(LIGHTHOUSE_V2_SESSION_ARCHIVED_EVENT, {
      detail: { sessionId },
    }),
  );
}

export const LIGHTHOUSE_V2_NEW_CHAT_EVENT = "lighthouse-v2:new-chat";

// Lets the sidebar reset an already-mounted chat page. router.push("/lighthouse")
// is a no-op when the URL was set via replaceState (Next's router never saw it),
// so the latest conversation needs a client-side reset signal.
export function notifyLighthouseV2NewChat() {
  if (typeof window === "undefined") return;
  window.dispatchEvent(new Event(LIGHTHOUSE_V2_NEW_CHAT_EVENT));
}
