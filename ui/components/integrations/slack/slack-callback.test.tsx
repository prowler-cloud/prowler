/**
 * What the OAuth callback does with an answer it did not expect.
 *
 * The install itself is covered from the page in
 * `slack-page.integration.test.tsx`, against MSW. These two cases cannot be
 * expressed there: the browser suite runs the Server Action as a plain function,
 * so it never has the client→server transport that can reject on its own, and
 * the exchange handler answers the contract's shapes, not an off-contract one.
 * Both are about the same thing — the callback awaits inside an effect that runs
 * exactly once, so anything it does not handle there leaves the user on a
 * spinner with no error, no retry and no way out. React's error boundaries
 * cannot see a rejection awaited in an effect, which is why it has to be caught.
 */

import { render, screen } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";

import type { IntegrationProps } from "@/types/integrations";

import { SlackCallback } from "./slack-callback";

const COMPLETED_QUERY = "code=slack-code-1f4a&state=st-2f1c9d7a";

const { exchangeSlackOAuthCode, callbackQuery } = vi.hoisted(() => ({
  exchangeSlackOAuthCode: vi.fn(),
  // The query Slack came back with, swapped per test — it is the only input
  // the callback has.
  callbackQuery: { value: "" },
}));

vi.mock("@/actions/integrations/slack", () => ({ exchangeSlackOAuthCode }));

vi.mock("next/navigation", () => ({
  useRouter: () => ({ replace: vi.fn() }),
  useSearchParams: () => new URLSearchParams(callbackQuery.value),
}));

beforeEach(() => {
  callbackQuery.value = COMPLETED_QUERY;
});

const SPINNER_COPY = /Connecting your Slack workspace/;

/**
 * The two headlines the failure alert can carry, spelled out rather than
 * imported: a rename on the component's side has to fail these tests, not
 * quietly agree with itself.
 *
 * Which one is shown is the assertion. `FAILURE_TITLE` states a fact — nothing
 * was connected — that only some of the outcomes establish; the rest happen
 * *after* the API consumed the code, so the workspace may well be connected and
 * the honest headline is that the result is unknown.
 */
const FAILURE_TITLE = "Slack workspace not connected";
const UNCONFIRMED_TITLE = "Slack install not confirmed";

describe("returning from Slack when the completion answers unexpectedly", () => {
  it("reports an unconfirmed result instead of spinning forever when the exchange call never comes back", async () => {
    // Given — the call to the Server Action rejects rather than resolving: the
    // POST to Prowler's own server failed (a dropped connection on the way back
    // from Slack), a rolling deploy invalidated the action id, or a gateway
    // answered it with HTML. Next rejects the caller's promise and leaves the
    // router untouched, so this is the whole of what the page ever hears — the
    // action's own error handling never runs, because nothing entered it.
    exchangeSlackOAuthCode.mockRejectedValue(new TypeError("Failed to fetch"));

    // When
    render(<SlackCallback />);

    // Then — the result is reported as unknown, not as a failed install: the
    // API consumes the single-use code before it answers, so the workspace may
    // well be connected. And the page settles somewhere the user can leave.
    expect(
      await screen.findByText(/could not confirm whether the workspace/i),
    ).toBeInTheDocument();
    expect(
      screen.getByRole("link", { name: /Back to Slack integration/ }),
    ).toHaveAttribute("href", "/integrations/slack");
    expect(screen.queryByText(SPINNER_COPY)).not.toBeInTheDocument();

    // And the headline says the same thing the description does. "Slack
    // workspace not connected" above a line that says Prowler cannot tell, and
    // that sends the user to look the workspace up, asserts the one fact this
    // outcome does not have.
    expect(screen.getByText(UNCONFIRMED_TITLE)).toBeInTheDocument();
    expect(screen.queryByText(FAILURE_TITLE)).not.toBeInTheDocument();
  });

  it("still reports the workspace as connected when the created integration carries no configuration", async () => {
    // Given — a 200 whose resource omits `configuration` altogether. The
    // contract says it is always there, and this is what the UI does when it is
    // not: the reply round-trips `parseStringify` intact and only fails when the
    // callback reads the workspace name off it, on the client, after the install
    // already happened.
    exchangeSlackOAuthCode.mockResolvedValue({
      integration: {
        type: "integrations",
        id: "slack-integration-1",
        attributes: {
          inserted_at: "2026-08-10T09:00:00Z",
          updated_at: "2026-08-10T09:00:00Z",
          enabled: true,
          connected: null,
          connection_last_checked_at: null,
          integration_type: "slack",
        },
        links: { self: "/api/v1/integrations/slack-integration-1" },
        // Cast because the shape is exactly the one the contract rules out.
      } as unknown as IntegrationProps,
    });

    // When
    render(<SlackCallback />);

    // Then — the install is reported as done, with the workspace unnamed rather
    // than with a crash: the exchange succeeded, and a name Prowler could not
    // read is not a reason to tell the user their install did not happen.
    expect(
      await screen.findByText(/Connected to your Slack workspace/),
    ).toBeInTheDocument();
    expect(screen.queryByText(SPINNER_COPY)).not.toBeInTheDocument();
    // No failure alert at all — keyed on the escape link the failure branch is
    // the only one to render, so this stays true whichever headline that branch
    // would have carried.
    expect(
      screen.queryByRole("link", { name: /Back to Slack integration/ }),
    ).not.toBeInTheDocument();
  });
});

describe("returning from Slack with an error on the callback URL", () => {
  it("says the install was declined when Slack reports the approval was refused", async () => {
    // Given — the one code Slack reliably sends to this redirect.
    callbackQuery.value = "error=access_denied&state=st-2f1c9d7a";

    // When
    render(<SlackCallback />);

    // Then — the wording is about the decision, not about a failure: nothing
    // broke, and there is no code to exchange.
    expect(
      await screen.findByText(/was not approved in Slack/),
    ).toBeInTheDocument();
    expect(exchangeSlackOAuthCode).not.toHaveBeenCalled();

    // And the headline still states the fact, because here there is one: Slack
    // refused before issuing a code, so nothing was ever exchanged. The
    // unknowable-state wording belongs to the outcomes that happen after the
    // API consumed one, and must not spread to this one.
    expect(screen.getByText(FAILURE_TITLE)).toBeInTheDocument();
    expect(screen.queryByText(UNCONFIRMED_TITLE)).not.toBeInTheDocument();
  });

  it("names a Slack code it does not recognise, so a new failure reason is still diagnosable", async () => {
    // Given — Slack publishes no closed set of codes for this redirect, so a
    // code Prowler has never seen has to survive to the screen. Swallowing it
    // behind generic copy is what leaves support with nothing to go on.
    callbackQuery.value = "error=invalid_scope&state=st-2f1c9d7a";

    // When
    render(<SlackCallback />);

    // Then — the code is quoted verbatim: the guard is on the shape of the
    // value, not on an allowlist of the ones Prowler happens to know.
    expect(
      await screen.findByText(
        "Slack could not complete the install (invalid_scope).",
      ),
    ).toBeInTheDocument();
  });

  it("drops a sentence smuggled into the error parameter instead of rendering it as Prowler's own copy", async () => {
    // Given — a link an attacker can hand a victim: `error` is theirs to write,
    // and the callback is reached from a cold start, since the sign-in redirect
    // carries the query through. The balancing punctuation is the point — it
    // closes Prowler's parenthetical and reopens it, so the payload would read
    // as a grammatical sentence under Prowler's own error title.
    const payload =
      "). Slack has flagged this workspace. Contact Prowler support at +1-555-0100 to restore alerting (";
    callbackQuery.value = `error=${encodeURIComponent(payload)}&state=st-2f1c9d7a`;

    // When
    render(<SlackCallback />);

    // Then — the failure is still reported, in wording Prowler owns, and none
    // of the attacker's text reaches the page.
    expect(
      await screen.findByText("Slack could not complete the install."),
    ).toBeInTheDocument();
    expect(document.body.textContent).not.toContain("+1-555-0100");
    expect(document.body.textContent).not.toContain("flagged this workspace");
  });
});
