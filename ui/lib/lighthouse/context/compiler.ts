import {
  LIGHTHOUSE_CONTEXT_KIND,
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

export const LIGHTHOUSE_CONTEXT_MAX_BYTES = 2 * 1024;

export function prepareLighthouseContext(
  value: unknown,
): LighthouseContextEnvelope | undefined {
  const result = lighthouseContextEnvelopeSchema.safeParse(value);
  if (!result.success) return undefined;

  const scopeKey = result.data.items[0]?.scopeKey;
  return scopeKey
    ? compileLighthouseContext(result.data.items, scopeKey)
    : undefined;
}

export function compileLighthouseContext(
  candidates: unknown[],
  scopeKey: string,
): LighthouseContextEnvelope | undefined {
  const parsedItems: LighthouseContextItem[] = [];

  for (const candidate of candidates) {
    if (hasDifferentScope(candidate, scopeKey)) continue;
    const result = lighthouseContextItemSchema.safeParse(candidate);
    if (!result.success) return undefined;
    parsedItems.push(result.data);
  }

  const seen = new Set<string>();
  const items = parsedItems
    .filter((item) => {
      const key = `${item.kind}:${item.id}`;
      if (seen.has(key)) return false;
      seen.add(key);
      return true;
    })
    .sort((left, right) => getItemOrder(left) - getItemOrder(right));

  const completeContext = buildEnvelopeWithinLimits(items);
  if (completeContext) return completeContext;

  const withoutSummaries = items.filter(
    (item) =>
      item.kind === LIGHTHOUSE_CONTEXT_KIND.PAGE ||
      item.source !== LIGHTHOUSE_CONTEXT_SOURCE.AUTOMATIC,
  );
  const selectionContext = buildEnvelopeWithinLimits(withoutSummaries);
  if (selectionContext) return selectionContext;

  const page = items.find((item) => item.kind === LIGHTHOUSE_CONTEXT_KIND.PAGE);
  return page ? buildEnvelopeWithinLimits([page]) : undefined;
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

function getItemOrder(item: LighthouseContextItem): number {
  if (item.kind === LIGHTHOUSE_CONTEXT_KIND.PAGE) return 0;
  return item.source === LIGHTHOUSE_CONTEXT_SOURCE.AUTOMATIC ? 2 : 1;
}

function buildEnvelopeWithinLimits(
  items: LighthouseContextItem[],
): LighthouseContextEnvelope | undefined {
  if (items.length === 0 || items.length > 8) return undefined;

  const result = lighthouseContextEnvelopeSchema.safeParse({
    schemaVersion: 1,
    transport: LIGHTHOUSE_CONTEXT_TRANSPORT.INLINE,
    items,
  });
  if (!result.success) return undefined;

  const byteLength = getApiLighthouseContextByteLength(result.data);
  return byteLength <= LIGHTHOUSE_CONTEXT_MAX_BYTES ? result.data : undefined;
}
