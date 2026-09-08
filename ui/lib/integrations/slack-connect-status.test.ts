import { describe, expect, it } from "vitest";

import {
  readSlackConnectOutcome,
  SLACK_CONNECT_STATUS,
  slackConnectQuery,
} from "./slack-connect-status";

describe("the Slack connect status contract", () => {
  it("round-trips every field the writer accepts", () => {
    const written = slackConnectQuery({
      status: SLACK_CONNECT_STATUS.RATE_LIMITED,
      retryAfterSeconds: 30,
    });

    expect(readSlackConnectOutcome(written)).toEqual({
      status: "rate_limited",
      reason: null,
      code: null,
      retryAfterSeconds: 30,
    });
  });

  it("keeps a token-shaped reason and code", () => {
    expect(
      slackConnectQuery({
        status: SLACK_CONNECT_STATUS.SLACK_ERROR,
        reason: "access_denied",
      }).get("slack_reason"),
    ).toBe("access_denied");

    expect(
      slackConnectQuery({
        status: SLACK_CONNECT_STATUS.ERROR,
        code: "slack_workspace_conflict",
      }).get("slack_code"),
    ).toBe("slack_workspace_conflict");
  });

  it("drops a reason or code that is not shaped like a token, on write and on read", () => {
    const written = slackConnectQuery({
      status: SLACK_CONNECT_STATUS.SLACK_ERROR,
      reason: "<script>alert(1)</script>",
      code: "A sentence, not a code.",
    });
    expect(Array.from(written.keys())).toEqual(["slack"]);

    // Read-side gate too: the URL is user-editable after the redirect.
    const handcrafted = new URLSearchParams(
      "slack=slack_error&slack_reason=Not%20a%20token&slack_code=<x>",
    );
    expect(readSlackConnectOutcome(handcrafted)).toEqual({
      status: "slack_error",
      reason: null,
      code: null,
      retryAfterSeconds: null,
    });
  });

  it("rounds a fractional retry up and drops one that is not a positive number", () => {
    expect(
      slackConnectQuery({
        status: SLACK_CONNECT_STATUS.RATE_LIMITED,
        retryAfterSeconds: 1.5,
      }).get("slack_retry"),
    ).toBe("2");

    for (const retryAfterSeconds of [
      0,
      -3,
      Number.NaN,
      Number.POSITIVE_INFINITY,
    ]) {
      expect(
        slackConnectQuery({
          status: SLACK_CONNECT_STATUS.RATE_LIMITED,
          retryAfterSeconds,
        }).get("slack_retry"),
      ).toBeNull();
    }

    expect(
      readSlackConnectOutcome(
        new URLSearchParams("slack=rate_limited&slack_retry=soon"),
      )?.retryAfterSeconds,
    ).toBeNull();
  });

  it("reads the statuses that travel alone, the expired one included", () => {
    for (const status of ["expired", "incomplete", "unavailable"]) {
      expect(
        readSlackConnectOutcome(new URLSearchParams(`slack=${status}`))?.status,
      ).toBe(status);
    }
  });

  it("reads no outcome from an unknown status or a plain page visit", () => {
    expect(
      readSlackConnectOutcome(
        new URLSearchParams("slack=definitely_not_a_status"),
      ),
    ).toBeNull();
    expect(readSlackConnectOutcome(new URLSearchParams(""))).toBeNull();
    expect(readSlackConnectOutcome(new URLSearchParams("foo=bar"))).toBeNull();
  });
});
