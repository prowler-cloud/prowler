/**
 * The Slack code → copy mapping, unit-tested because most of the codes it
 * covers belong to flows this layer does not have yet: the channel picker, the
 * test message and the disconnect all lean on the same mapping, and each of
 * their conditions is a code that has to already resolve to the right words.
 */

import { describe, expect, it } from "vitest";

import {
  isSlackTokenErrorCode,
  SLACK_ERROR_CODE,
  SLACK_ERROR_MESSAGES,
  SLACK_GENERIC_ERROR_MESSAGE,
  SLACK_RATE_LIMITED_MESSAGE,
  SLACK_TOKEN_ERROR_CODES,
  readSlackFailure,
  slackErrorMessage,
  slackRateLimitMessage,
} from "./slack-errors";

describe("slackErrorMessage", () => {
  it("prefers the code's own copy over the API's wording", () => {
    // Given — the machine-readable reason and human copy disagree, which they
    // always do: `detail` states the condition, the code's copy resolves it.
    const failure = {
      code: SLACK_ERROR_CODE.WORKSPACE_CONFLICT,
      detail:
        "This tenant is already connected to a different Slack workspace.",
    };

    // Then
    expect(slackErrorMessage(failure)).toBe(
      SLACK_ERROR_MESSAGES[SLACK_ERROR_CODE.WORKSPACE_CONFLICT],
    );
    expect(slackErrorMessage(failure)).toMatch(/Disconnect it/);
  });

  it("tells the user how to grant a scope Prowler is missing", () => {
    // A missing scope is fixable by the person reading it, so the copy has to
    // name the fix rather than report that something went wrong.
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
      // Given a token the Slack grant no longer honours — revoked, invalid,
      // inactive or expired — no retry helps, so all four say the same thing.
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
    // A code this UI has nothing better to say about is not a reason to hide
    // what the API said.
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
    // Given — the shape the API answers with: a string status, the reason in
    // `code`, and a pointer at the document rather than at an attribute.
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

    // When
    const failure = await readSlackFailure(response);

    // Then
    expect(failure).toEqual({
      status: 429,
      code: null,
      detail: "Slack is rate limiting requests from Prowler.",
      retryAfterSeconds: 30,
    });
  });

  it("survives a body that is not JSON:API at all", async () => {
    // A 502 from a proxy carries HTML, and the status is still the answer.
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
