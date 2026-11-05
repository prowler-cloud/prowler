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

export const LIGHTHOUSE_V2_CONFIGURATIONS_CHANGED_EVENT =
  "lighthouse-v2:configurations-changed";

// Fired after provider configuration CRUD so cached chat configs (the panel
// keeps one at module scope) can invalidate and reload.
export function notifyLighthouseV2ConfigurationsChanged() {
  if (typeof window === "undefined") return;
  window.dispatchEvent(new Event(LIGHTHOUSE_V2_CONFIGURATIONS_CHANGED_EVENT));
}

// Typed subscribe helpers: each returns an unsubscribe function so consumers
// never hand-roll addEventListener plus the CustomEvent detail cast.
function subscribe(eventName: string, handler: (event: Event) => void) {
  if (typeof window === "undefined") return () => {};
  window.addEventListener(eventName, handler);
  return () => window.removeEventListener(eventName, handler);
}

export function onLighthouseV2SessionsChanged(callback: () => void) {
  return subscribe(LIGHTHOUSE_V2_SESSIONS_CHANGED_EVENT, callback);
}

export function onLighthouseV2SessionArchived(
  callback: (sessionId: string) => void,
) {
  return subscribe(LIGHTHOUSE_V2_SESSION_ARCHIVED_EVENT, (event) => {
    const sessionId = (event as CustomEvent<{ sessionId: string }>).detail
      ?.sessionId;
    if (sessionId) callback(sessionId);
  });
}

export function onLighthouseV2NewChat(callback: () => void) {
  return subscribe(LIGHTHOUSE_V2_NEW_CHAT_EVENT, callback);
}

export function onLighthouseV2ConfigurationsChanged(callback: () => void) {
  return subscribe(LIGHTHOUSE_V2_CONFIGURATIONS_CHANGED_EVENT, callback);
}
