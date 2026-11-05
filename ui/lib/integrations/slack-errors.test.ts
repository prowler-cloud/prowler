/**
 * Unit-tested because the mapping carries copy for codes no page-level flow can
 * be driven into — `no_permission`, `invalid_auth`, `account_inactive`.
 */

import { describe, expect, it } from "vitest";

import {
  isSlackTokenErrorCode,
  SLACK_ERROR_CODE,
  SLACK_ERROR_MESSAGES,
  SLACK_GENERIC_ERROR_MESSAGE,
  SLACK_RATE_LIMITED_MESSAGE,
  SLACK_REASON_TOKEN,
  SLACK_TOKEN_ERROR_CODES,
  readSlackFailure,
  slackErrorMessage,
  slackRateLimitMessage,
} from "./slack-errors";

describe("slackErrorMessage", () => {
  it("prefers the code's own copy over the API's wording", () => {
    // `detail` states the condition; the code's copy states the fix.
    const failure = {
      code: SLACK_ERROR_CODE.WORKSPACE_CONFLICT,
      detail:
        "This tenant is already connected to a different Slack workspace.",
    };

    expect(slackErrorMessage(failure)).toBe(
      SLACK_ERROR_MESSAGES[SLACK_ERROR_CODE.WORKSPACE_CONFLICT],
    );
    expect(slackErrorMessage(failure)).toMatch(/Disconnect it/);
  });

  it("tells the user how to grant a scope Prowler is missing", () => {
    // A missing scope is fixable by the reader, so the copy names the fix.
    const message = slackErrorMessage({
      code: SLACK_ERROR_CODE.MISSING_SCOPE,
      detail: "missing_scope",
    });

    expect(message).toMatch(/Connect the workspace again/);
    expect(message).not.toMatch(/missing_scope/);
  });

  it("says what to do about each channel refusal", () => {
    expect(
      slackErrorMessage({ code: SLACK_ERROR_CODE.CHANNEL_NOT_FOUND }),
    ).toMatch(/Choose another one/);
    expect(
      slackErrorMessage({ code: SLACK_ERROR_CODE.NOT_IN_CHANNEL }),
    ).toMatch(/Invite @Prowler/);
    expect(slackErrorMessage({ code: SLACK_ERROR_CODE.NO_PERMISSION })).toMatch(
      /Choose another channel/,
    );
  });

  it("points every dead-credential code at reconnecting, not at retrying", () => {
    for (const code of SLACK_TOKEN_ERROR_CODES) {
      // Revoked, invalid, inactive or expired: no retry helps for any of them.
      expect(slackErrorMessage({ code })).toMatch(
        /Connect the workspace again to restore access/,
      );
      expect(isSlackTokenErrorCode(code)).toBe(true);
    }
  });

  it("does not treat an actionable refusal as a dead credential", () => {
    expect(isSlackTokenErrorCode(SLACK_ERROR_CODE.MISSING_SCOPE)).toBe(false);
    expect(isSlackTokenErrorCode(null)).toBe(false);
    expect(isSlackTokenErrorCode(undefined)).toBe(false);
  });

  it("falls back to the API's detail for a code it does not know", () => {
    expect(
      slackErrorMessage({
        code: "some_future_slack_reason",
        detail: "Slack said no.",
      }),
    ).toBe("Slack said no.");
  });

  it("falls back to the generic line when there is neither", () => {
    expect(slackErrorMessage({ code: null, detail: null })).toBe(
      SLACK_GENERIC_ERROR_MESSAGE,
    );
    expect(slackErrorMessage(null)).toBe(SLACK_GENERIC_ERROR_MESSAGE);
    expect(
      slackErrorMessage({ detail: "   " }, "Could not read channels."),
    ).toBe("Could not read channels.");
  });

  it("falls back only for a code the mapping does not cover", () => {
    const FALLBACK = "Slack refused it (is_archived).";

    expect(
      slackErrorMessage({ code: SLACK_ERROR_CODE.NOT_IN_CHANNEL }, FALLBACK),
    ).toBe(SLACK_ERROR_MESSAGES[SLACK_ERROR_CODE.NOT_IN_CHANNEL]);
    // No `detail`: one holding the same token would make the raw token the
    // whole message again.
    expect(slackErrorMessage({ code: "is_archived" }, FALLBACK)).toBe(FALLBACK);
  });
});

describe("SLACK_REASON_TOKEN", () => {
  it("recognises a reason code and refuses anything that reads as a sentence", () => {
    // Slack publishes no closed set of reasons, so the guard is on shape rather
    // than an allowlist.
    for (const reason of [
      "is_archived",
      "restricted_action",
      "team_access_not_granted",
      "ekm_access_denied",
      "messages_tab_disabled",
    ]) {
      expect(SLACK_REASON_TOKEN.test(reason)).toBe(true);
    }

    for (const prose of [
      "Slack rejected the message: the channel is archived.",
      "). Contact support at +1-555-0100 (",
      "",
      "a".repeat(49),
    ]) {
      expect(SLACK_REASON_TOKEN.test(prose)).toBe(false);
    }
  });
});

describe("slackRateLimitMessage", () => {
  it("names the wait Slack asked for", () => {
    expect(slackRateLimitMessage(30)).toMatch(/about 30 seconds/);
    expect(slackRateLimitMessage(1)).toMatch(/about 1 second\b/);
    expect(slackRateLimitMessage(90)).toMatch(/about 2 minutes/);
  });

  it("still says to come back when Slack named no wait", () => {
    expect(slackRateLimitMessage(null)).toBe(SLACK_RATE_LIMITED_MESSAGE);
    expect(slackRateLimitMessage(0)).toBe(SLACK_RATE_LIMITED_MESSAGE);
  });
});

describe("readSlackFailure", () => {
  it("reads the code, the detail and the wait off a JSON:API refusal", async () => {
    const response = new Response(
      JSON.stringify({
        errors: [
          {
            status: "429",
            detail: "Slack is rate limiting requests from Prowler.",
            source: { pointer: "/data" },
          },
        ],
      }),
      { status: 429, headers: { "Retry-After": "30" } },
    );

    const failure = await readSlackFailure(response);

    expect(failure).toEqual({
      status: 429,
      code: null,
      detail: "Slack is rate limiting requests from Prowler.",
      retryAfterSeconds: 30,
    });
  });

  it("survives a body that is not JSON:API at all", async () => {
    const failure = await readSlackFailure(
      new Response("<html>Bad gateway</html>", { status: 502 }),
    );

    expect(failure).toEqual({
      status: 502,
      code: null,
      detail: null,
      retryAfterSeconds: null,
    });
  });

  it("ignores a Retry-After it cannot use", async () => {
    const failure = await readSlackFailure(
      new Response("{}", { status: 429, headers: { "Retry-After": "soon" } }),
    );

    expect(failure.retryAfterSeconds).toBeNull();
  });
});
