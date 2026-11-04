import { describe, expect, it } from "vitest";

import {
  isSelectableRecipient,
  recipientStatusLabel,
  toggleId,
} from "./notifications";
import { DEFAULT_REALTIME_NOTIFICATIONS } from "./policy-schema";
import { alertsSummary } from "./setup";

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

  it("summarises nothing sent when no channel is on", () => {
    expect(alertsSummary(DEFAULT_REALTIME_NOTIFICATIONS, null)).toBe(
      "Slack off · email off",
    );
  });

  it("names the channels and recipients in the summary", () => {
    expect(
      alertsSummary(
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
    ).toBe("Slack #security, C9 · email to 1 recipient · critical and above");
  });
});
