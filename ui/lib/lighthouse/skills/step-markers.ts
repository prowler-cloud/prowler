// SSE deltas split text at arbitrary points, so a "[[step:3]]" marker can
// arrive across two chunks. Callers thread `carry` (the held-back suffix that
// might still become a marker) between invocations and flush it as plain text
// when the stream ends.
// Shared digit cap: the complete-marker matcher, the partial-suffix matcher
// and the hold-back window must agree, or a marker split right at the limit
// gets half-emitted as text and its step silently dropped.
const MAX_STEP_DIGITS = 4;
const COMPLETE_MARKER = new RegExp(
  `\\[\\[step:(\\d{1,${MAX_STEP_DIGITS}})\\]\\]`,
  "g",
);
const PARTIAL_MARKER = new RegExp(
  `^\\[\\[step:\\d{0,${MAX_STEP_DIGITS}}\\]?$`,
);
const MARKER_PREFIX = "[[step:";
// Longest suffix that can still grow into a marker: prefix + digits + one "]".
const MARKER_HOLD_WINDOW = MARKER_PREFIX.length + MAX_STEP_DIGITS + 1;

export interface StepMarkerResult {
  text: string;
  carry: string;
  steps: number[];
}

// Cleans persisted assistant text: the backend stores the model's raw output,
// markers included, so anything rendered from a reloaded message must strip
// them. Marker-only lines (the model sometimes emits them as list items) are
// removed whole so no empty bullets remain; inline markers are excised.
export function stripStepMarkers(text: string): string {
  return text
    .replace(/^[ \t]*(?:[-*+]\s+)?\[\[step:\d+\]\][ \t]*$\r?\n?/gm, "")
    .replace(/\[\[step:\d+\]\][ \t]*/g, "");
}

export function consumeStepMarkers(
  carry: string,
  chunk: string,
): StepMarkerResult {
  const input = `${carry}${chunk}`;
  const steps: number[] = [];
  const stripped = input.replace(COMPLETE_MARKER, (_, step: string) => {
    steps.push(Number(step));
    return "";
  });

  const heldFrom = findPotentialMarkerStart(stripped);
  return {
    text: stripped.slice(0, heldFrom),
    carry: stripped.slice(heldFrom),
    steps,
  };
}

// Index where a suffix begins that could still grow into a marker; text length
// when there is none. Checks longest suffix first so "[[step:1[[s" holds from
// the second candidate, not the first.
function findPotentialMarkerStart(text: string): number {
  const windowStart = Math.max(0, text.length - MARKER_HOLD_WINDOW);
  for (let index = windowStart; index < text.length; index += 1) {
    if (isPotentialMarkerPrefix(text.slice(index))) {
      return index;
    }
  }
  return text.length;
}

function isPotentialMarkerPrefix(suffix: string): boolean {
  if (MARKER_PREFIX.startsWith(suffix)) return true;
  return PARTIAL_MARKER.test(suffix);
}
