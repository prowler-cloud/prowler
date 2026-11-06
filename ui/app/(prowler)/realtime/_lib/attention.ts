import { shortArn } from "@/app/(prowler)/realtime/_lib/display";
import {
  REALTIME_ACTION_STATUS,
  REALTIME_DETECTION_STATUS,
  type RealtimeAction,
  type RealtimeDetection,
} from "@/app/(prowler)/realtime/_types";

/** Action outcomes a person has to look at. */
export const ATTENTION_ACTION_STATUSES: readonly string[] = [
  REALTIME_ACTION_STATUS.FIX_FAILED,
  REALTIME_ACTION_STATUS.STILL_FAILING,
  REALTIME_ACTION_STATUS.PR_BLOCKED,
];

export const ATTENTION_ITEM_KIND = {
  DETECTION: "detection",
  ACTION: "action",
} as const;
export type AttentionItemKind =
  (typeof ATTENTION_ITEM_KIND)[keyof typeof ATTENTION_ITEM_KIND];

export interface AttentionItem {
  kind: AttentionItemKind;
  id: string;
  at: string;
  severity: string;
  title: string;
  /** Resource, region and who did it, as one line. */
  context: string;
  status: string;
}

const time = (value: string) => {
  const parsed = new Date(value).getTime();
  return Number.isNaN(parsed) ? 0 : parsed;
};

const joinContext = (...parts: string[]) => parts.filter(Boolean).join(" · ");

/**
 * Confirmed violations and responses that did not finish, newest first. The
 * lists may be unfiltered (demo data), so the statuses are checked here too.
 */
export const toAttentionItems = (
  detections: RealtimeDetection[],
  actions: RealtimeAction[],
  limit = 6,
): AttentionItem[] =>
  [
    ...detections
      .filter(
        (detection) => detection.status === REALTIME_DETECTION_STATUS.VIOLATION,
      )
      .map(
        (detection): AttentionItem => ({
          kind: ATTENTION_ITEM_KIND.DETECTION,
          id: detection.id,
          at: detection.event_time,
          severity: detection.severity,
          title: detection.title || detection.rule_id,
          context: joinContext(
            detection.resource,
            detection.region,
            detection.actor.startsWith("arn:")
              ? shortArn(detection.actor)
              : detection.actor,
          ),
          status: detection.status,
        }),
      ),
    ...actions
      .filter((action) => ATTENTION_ACTION_STATUSES.includes(action.status))
      .map(
        (action): AttentionItem => ({
          kind: ATTENTION_ITEM_KIND.ACTION,
          id: action.id,
          at: action.inserted_at,
          severity: action.severity,
          title: action.summary || action.check_id,
          context: joinContext(action.resource_uid, action.region),
          status: action.status,
        }),
      ),
  ]
    .sort((a, b) => time(b.at) - time(a.at))
    .slice(0, limit);
