import {
  LIGHTHOUSE_CONTEXT_KIND,
  LIGHTHOUSE_CONTEXT_LIMIT,
  LIGHTHOUSE_CONTEXT_SOURCE,
  LIGHTHOUSE_CONTEXT_TRANSPORT,
  type LighthouseContextEnvelope,
  type LighthouseContextItem,
} from "@/types/lighthouse-context";

import {
  lighthouseContextEnvelopeSchema,
  lighthouseContextItemSchema,
} from "./schema";
import { getApiLighthouseContextByteLength } from "./transport";

const LIGHTHOUSE_CONTEXT_MAX_BYTES = 4 * 1024;

export function prepareLighthouseContext(
  value: unknown,
): LighthouseContextEnvelope | undefined {
  // Only the wrapper is checked here; compileLighthouseContext validates each
  // item so a single malformed one drops alone instead of voiding the send.
  if (
    typeof value !== "object" ||
    value === null ||
    !("items" in value) ||
    !Array.isArray(value.items)
  ) {
    return undefined;
  }

  const scopeKey = findCandidateScopeKey(value.items);
  return scopeKey ? compileLighthouseContext(value.items, scopeKey) : undefined;
}

function findCandidateScopeKey(candidates: unknown[]): string | undefined {
  // Scope comes from the first item that survives validation — a malformed
  // item carrying a foreign scopeKey must not decide the compiled scope.
  for (const candidate of candidates) {
    const result = lighthouseContextItemSchema.safeParse(candidate);
    if (result.success) return result.data.scopeKey;
  }
  return undefined;
}

export function compileLighthouseContext(
  candidates: unknown[],
  scopeKey: string,
): LighthouseContextEnvelope | undefined {
  const parsedItems: LighthouseContextItem[] = [];

  for (const candidate of candidates) {
    if (hasDifferentScope(candidate, scopeKey)) continue;
    const result = lighthouseContextItemSchema.safeParse(candidate);
    // A malformed candidate (a null in an optional field, or a kind this
    // build doesn't know) drops alone instead of voiding the whole envelope.
    if (!result.success) continue;
    parsedItems.push(result.data);
  }

  const seen = new Set<string>();
  const items = parsedItems
    .sort((left, right) => getItemOrder(left) - getItemOrder(right))
    .filter((item) => {
      const key = `${item.kind}:${item.id}`;
      if (seen.has(key)) return false;
      seen.add(key);
      return true;
    });

  return buildEnvelopeWithProgressiveDegradation(items);
}

function hasDifferentScope(candidate: unknown, scopeKey: string): boolean {
  return (
    typeof candidate === "object" &&
    candidate !== null &&
    "scopeKey" in candidate &&
    typeof candidate.scopeKey === "string" &&
    candidate.scopeKey !== scopeKey
  );
}

// Eviction drops items from the end, so automatic items rank by how much
// posture signal they carry: scores and summaries outlive provider labels.
const AUTOMATIC_KIND_ORDER: Record<LighthouseContextItem["kind"], number> = {
  [LIGHTHOUSE_CONTEXT_KIND.PAGE]: 0,
  [LIGHTHOUSE_CONTEXT_KIND.COMPLIANCE]: 1,
  [LIGHTHOUSE_CONTEXT_KIND.FINDING]: 2,
  [LIGHTHOUSE_CONTEXT_KIND.ATTACK_PATH]: 3,
  [LIGHTHOUSE_CONTEXT_KIND.RESOURCE]: 4,
  [LIGHTHOUSE_CONTEXT_KIND.SCAN]: 5,
  [LIGHTHOUSE_CONTEXT_KIND.ALERT]: 6,
  [LIGHTHOUSE_CONTEXT_KIND.PROVIDER]: 7,
};

function getItemOrder(item: LighthouseContextItem): number {
  if (item.kind === LIGHTHOUSE_CONTEXT_KIND.PAGE) return 0;
  if (item.source === LIGHTHOUSE_CONTEXT_SOURCE.FOCUSED) return 1;
  if (item.source !== LIGHTHOUSE_CONTEXT_SOURCE.AUTOMATIC) return 2;
  return 3 + AUTOMATIC_KIND_ORDER[item.kind];
}

function buildEnvelopeWithinLimits(
  items: LighthouseContextItem[],
): LighthouseContextEnvelope | undefined {
  if (items.length === 0 || items.length > LIGHTHOUSE_CONTEXT_LIMIT.ITEMS) {
    return undefined;
  }

  const result = lighthouseContextEnvelopeSchema.safeParse({
    schemaVersion: 1,
    transport: LIGHTHOUSE_CONTEXT_TRANSPORT.INLINE,
    items,
  });
  if (!result.success) return undefined;

  const byteLength = getApiLighthouseContextByteLength(result.data);
  return byteLength <= LIGHTHOUSE_CONTEXT_MAX_BYTES ? result.data : undefined;
}

function buildEnvelopeWithProgressiveDegradation(
  items: LighthouseContextItem[],
): LighthouseContextEnvelope | undefined {
  const retainedItems = items.slice(0, LIGHTHOUSE_CONTEXT_LIMIT.ITEMS);

  while (retainedItems.length > 0) {
    const context = buildEnvelopeWithinLimits(retainedItems);
    if (context) return context;
    retainedItems.pop();
  }

  return undefined;
}
