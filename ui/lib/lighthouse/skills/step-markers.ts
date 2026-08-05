// SSE deltas split text at arbitrary points, so a "[[step:3]]" marker can
// arrive across two chunks. Callers thread `carry` (the held-back suffix that
// might still become a marker) between invocations and flush it as plain text
// when the stream ends.
const COMPLETE_MARKER = /\[\[step:(\d+)\]\]/g;
const MARKER_PREFIX = "[[step:";

export interface StepMarkerResult {
  text: string;
  carry: string;
  steps: number[];
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
  const windowStart = Math.max(0, text.length - MARKER_PREFIX.length - 12);
  for (let index = windowStart; index < text.length; index += 1) {
    if (isPotentialMarkerPrefix(text.slice(index))) {
      return index;
    }
  }
  return text.length;
}

function isPotentialMarkerPrefix(suffix: string): boolean {
  if (MARKER_PREFIX.startsWith(suffix)) return true;
  return /^\[\[step:\d*\]?$/.test(suffix);
}
