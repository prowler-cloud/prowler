import {
  REALTIME_ACTION_STATUS,
  type RealtimeActionStatus,
  type RealtimeTimelineAction,
} from "@/app/(prowler)/realtime/_types";

/** What an action on the posture chart did, in legend order. */
export const TIMELINE_GROUP = {
  FIXED: "fixed",
  CODE: "code",
  DRY_RUN: "dry_run",
  FAILED: "failed",
  OTHER: "other",
} as const;
export type TimelineGroup =
  (typeof TIMELINE_GROUP)[keyof typeof TIMELINE_GROUP];

export const TIMELINE_GROUP_LABELS: Record<TimelineGroup, string> = {
  [TIMELINE_GROUP.FIXED]: "Auto-fix",
  [TIMELINE_GROUP.CODE]: "Pull request",
  [TIMELINE_GROUP.DRY_RUN]: "Dry run",
  [TIMELINE_GROUP.FAILED]: "Did not finish",
  [TIMELINE_GROUP.OTHER]: "Other",
};

const GROUP_BY_STATUS: Partial<Record<RealtimeActionStatus, TimelineGroup>> = {
  [REALTIME_ACTION_STATUS.APPLIED]: TIMELINE_GROUP.FIXED,
  [REALTIME_ACTION_STATUS.FIXED_VERIFIED]: TIMELINE_GROUP.FIXED,
  [REALTIME_ACTION_STATUS.PR_OPENED]: TIMELINE_GROUP.CODE,
  [REALTIME_ACTION_STATUS.PR_READY]: TIMELINE_GROUP.CODE,
  [REALTIME_ACTION_STATUS.DRY_RUN]: TIMELINE_GROUP.DRY_RUN,
  [REALTIME_ACTION_STATUS.FIX_FAILED]: TIMELINE_GROUP.FAILED,
  [REALTIME_ACTION_STATUS.STILL_FAILING]: TIMELINE_GROUP.FAILED,
  [REALTIME_ACTION_STATUS.PR_BLOCKED]: TIMELINE_GROUP.FAILED,
};

export const timelineGroup = (status: string): TimelineGroup =>
  GROUP_BY_STATUS[status as RealtimeActionStatus] ?? TIMELINE_GROUP.OTHER;

export interface TimelineGroupCount {
  group: TimelineGroup;
  count: number;
}

export const countTimelineGroups = (
  actions: RealtimeTimelineAction[],
): TimelineGroupCount[] =>
  Object.values(TIMELINE_GROUP)
    .map((group) => ({
      group,
      count: actions.filter((action) => timelineGroup(action.status) === group)
        .length,
    }))
    .filter(({ count }) => count > 0);

export const latestTimelineActions = (
  actions: RealtimeTimelineAction[],
  limit: number,
): RealtimeTimelineAction[] =>
  [...actions]
    .sort((a, b) => new Date(b.at).getTime() - new Date(a.at).getTime())
    .slice(0, limit);
