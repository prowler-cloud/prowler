import { describe, expect, it } from "vitest";

import {
  isSelectableRecipient,
  notificationsSummary,
  recipientStatusLabel,
  sameNotifications,
  toggleId,
} from "./notifications";
import { DEFAULT_REALTIME_NOTIFICATIONS } from "./policy-schema";

describe("alert helpers", () => {
  it("only lets a confirmed recipient be selected", () => {
    expect(
      isSelectableRecipient({ id: "1", email: "a@x.io", status: "confirmed" }),
    ).toBe(true);
    for (const status of ["pending", "unsubscribed", "bounced"]) {
      expect(isSelectableRecipient({ id: "1", email: "a@x.io", status })).toBe(
        false,
      );
    }
    expect(recipientStatusLabel("unsubscribed")).toBe("Unsubscribed");
  });

  it("adds and removes an id once", () => {
    expect(toggleId(["a"], "b", true)).toEqual(["a", "b"]);
    expect(toggleId(["a", "b"], "b", true)).toEqual(["a", "b"]);
    expect(toggleId(["a", "b"], "a", false)).toEqual(["b"]);
    expect(toggleId(["a"], "z", false)).toEqual(["a"]);
  });

  it("compares alert settings by content", () => {
    expect(
      sameNotifications(
        DEFAULT_REALTIME_NOTIFICATIONS,
        structuredClone(DEFAULT_REALTIME_NOTIFICATIONS),
      ),
    ).toBe(true);
    expect(
      sameNotifications(DEFAULT_REALTIME_NOTIFICATIONS, {
        ...DEFAULT_REALTIME_NOTIFICATIONS,
        min_severity: "low",
      }),
    ).toBe(false);
  });

  it("summarises nothing when no channel is on", () => {
    expect(notificationsSummary(DEFAULT_REALTIME_NOTIFICATIONS)).toEqual([]);
  });

  it("names the channels and recipients in the summary", () => {
    expect(
      notificationsSummary(
        {
          min_severity: "critical",
          slack: { enabled: true, channel_ids: ["C1", "C9"] },
          email: { enabled: true, recipient_ids: ["r1"] },
        },
        {
          slack: [{ integration_id: "i", channel_id: "C1", name: "security" }],
          email: [{ id: "r1", email: "a@x.io", status: "confirmed" }],
        },
      ),
    ).toEqual([
      "Slack: #security, C9",
      "Email: a@x.io",
      "From severity: Critical",
    ]);
  });
});
