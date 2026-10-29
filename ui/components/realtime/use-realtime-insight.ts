"use client";

import { getRealtimeDemo, getRealtimeInsight } from "@/actions/realtime";
import { useRealtimeResource } from "@/components/realtime/use-realtime-resource";
import type {
  RealtimeInsightKind,
  RealtimeInsightPayloads,
  RealtimeResult,
} from "@/types/realtime";

/**
 * One computed view of an account. In demo mode it comes from the sample data
 * instead (no provider needed, never refreshed): a view is either the account's
 * or the sample's, never both.
 */
export function useRealtimeInsight<K extends RealtimeInsightKind>(
  kind: K,
  providerId: string,
  demo: boolean,
  intervalMs?: number,
) {
  return useRealtimeResource<RealtimeInsightPayloads[K]>(
    () =>
      (demo
        ? getRealtimeDemo(kind)
        : getRealtimeInsight(kind, providerId)) as Promise<
        RealtimeResult<RealtimeInsightPayloads[K]>
      >,
    demo ? `demo:${kind}` : `${kind}:${providerId}`,
    { intervalMs: demo ? undefined : intervalMs },
  );
}
