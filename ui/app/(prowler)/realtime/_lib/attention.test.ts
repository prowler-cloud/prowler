import { describe, expect, it } from "vitest";

import {
  REALTIME_ACTION_KIND,
  REALTIME_ACTION_STATUS,
  REALTIME_DETECTION_STATUS,
  type RealtimeAction,
  type RealtimeDetection,
} from "@/app/(prowler)/realtime/_types";

import { ATTENTION_ITEM_KIND, toAttentionItems } from "./attention";

const detection = (
  overrides: Partial<RealtimeDetection>,
): RealtimeDetection => ({
  id: "d1",
  provider_id: "p",
  event_id: "e1",
  event_time: "2026-11-04T10:00:00Z",
  region: "eu-west-1",
  rule_id: "sg_open_all",
  title: "Security group open to the internet",
  severity: "critical",
  actor: "role/ci",
  resource: "sg-1",
  check_ids: [],
  requirements: [],
  status: REALTIME_DETECTION_STATUS.VIOLATION,
  note: "",
  verified_at: null,
  ...overrides,
});

const action = (overrides: Partial<RealtimeAction>): RealtimeAction => ({
  id: "a1",
  provider_id: "p",
  detection_id: null,
  kind: REALTIME_ACTION_KIND.SELF_FIX,
  status: REALTIME_ACTION_STATUS.FIX_FAILED,
  check_id: "rds_instance_no_public_access",
  resource_uid: "orders-db",
  region: "eu-west-1",
  severity: "high",
  summary: "Fix failed: AccessDenied",
  pr_url: "",
  branch: "",
  revertible: false,
  inserted_at: "2026-11-04T11:00:00Z",
  ...overrides,
});

describe("toAttentionItems", () => {
  it("merges violations and unfinished responses, newest first", () => {
    const items = toAttentionItems(
      [detection({ id: "old", event_time: "2026-11-04T09:00:00Z" })],
      [action({ id: "new" })],
    );

    expect(items.map((item) => [item.kind, item.id])).toEqual([
      [ATTENTION_ITEM_KIND.ACTION, "new"],
      [ATTENTION_ITEM_KIND.DETECTION, "old"],
    ]);
    expect(items[1].context).toBe("sg-1 · eu-west-1 · role/ci");
  });

  it("drops what does not need a person, as unfiltered demo lists include it", () => {
    const items = toAttentionItems(
      [detection({ status: REALTIME_DETECTION_STATUS.COMPLIANT })],
      [
        action({ status: REALTIME_ACTION_STATUS.FIXED_VERIFIED }),
        action({ id: "blocked", status: REALTIME_ACTION_STATUS.PR_BLOCKED }),
      ],
    );

    expect(items.map((item) => item.id)).toEqual(["blocked"]);
  });

  it("keeps at most the limit", () => {
    const detections = Array.from({ length: 5 }, (_, index) =>
      detection({ id: `d${index}` }),
    );

    expect(toAttentionItems(detections, [], 3)).toHaveLength(3);
  });
});
