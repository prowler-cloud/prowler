import { describe, expect, it } from "vitest";

import type { RealtimeTimelineAction } from "@/app/(prowler)/realtime/_types";

import {
  countTimelineGroups,
  latestTimelineActions,
  TIMELINE_GROUP,
  timelineGroup,
} from "./timeline";

const action = (
  status: string,
  at = "2026-11-05T10:00:00Z",
): RealtimeTimelineAction =>
  ({
    at,
    kind: "self_fix",
    status,
    summary: status,
  }) as RealtimeTimelineAction;

describe("posture timeline actions", () => {
  it("groups each action by what it did to the account", () => {
    expect(timelineGroup("fixed_verified")).toBe(TIMELINE_GROUP.FIXED);
    expect(timelineGroup("applied")).toBe(TIMELINE_GROUP.FIXED);
    expect(timelineGroup("pr_opened")).toBe(TIMELINE_GROUP.CODE);
    expect(timelineGroup("dry_run")).toBe(TIMELINE_GROUP.DRY_RUN);
    expect(timelineGroup("still_failing")).toBe(TIMELINE_GROUP.FAILED);
    expect(timelineGroup("pr_blocked")).toBe(TIMELINE_GROUP.FAILED);
    expect(timelineGroup("reverted")).toBe(TIMELINE_GROUP.OTHER);
    expect(timelineGroup("something_new")).toBe(TIMELINE_GROUP.OTHER);
  });

  it("counts the groups in legend order and leaves out empty ones", () => {
    expect(
      countTimelineGroups([
        action("dry_run"),
        action("fixed_verified"),
        action("dry_run"),
        action("fix_failed"),
      ]),
    ).toEqual([
      { group: TIMELINE_GROUP.FIXED, count: 1 },
      { group: TIMELINE_GROUP.DRY_RUN, count: 2 },
      { group: TIMELINE_GROUP.FAILED, count: 1 },
    ]);
  });

  it("lists the newest actions first", () => {
    const actions = [
      action("dry_run", "2026-11-01T10:00:00Z"),
      action("pr_opened", "2026-11-05T10:00:00Z"),
      action("applied", "2026-11-03T10:00:00Z"),
    ];
    expect(
      latestTimelineActions(actions, 2).map((item) => item.status),
    ).toEqual(["pr_opened", "applied"]);
  });
});
