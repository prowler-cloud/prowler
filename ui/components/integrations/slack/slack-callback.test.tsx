/**
 * The cases `slack-page.integration.test.tsx` cannot express: it runs the Server
 * Action as a plain function, so there is no client→server transport to reject,
 * and its handler only answers the contract's shapes. React error boundaries
 * cannot see a rejection awaited in an effect, so an uncaught one leaves the
 * user on the spinner with no error and no way out.
 */

import { render, screen } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";

import type { IntegrationProps } from "@/types/integrations";

import { SlackCallback } from "./slack-callback";

const COMPLETED_QUERY = "code=slack-code-1f4a&state=st-2f1c9d7a";

const { exchangeSlackOAuthCode, callbackQuery, routerReplace } = vi.hoisted(
  () => ({
    exchangeSlackOAuthCode: vi.fn(),
    callbackQuery: { value: "" },
    routerReplace: vi.fn(),
  }),
);

vi.mock("@/actions/integrations/slack", () => ({ exchangeSlackOAuthCode }));

// One router across renders, so the redirect off the spent code is assertable.
const router = { replace: routerReplace };

vi.mock("next/navigation", () => ({
  useRouter: () => router,
  useSearchParams: () => new URLSearchParams(callbackQuery.value),
}));

beforeEach(() => {
  callbackQuery.value = COMPLETED_QUERY;
  routerReplace.mockClear();
});

const SPINNER_COPY = /Connecting your Slack workspace/;

/**
 * Literals, not imports: a rename on the component's side has to fail here.
 * `FAILURE_TITLE` claims nothing was connected, which only holds for outcomes
 * that happen before the API consumed the code.
 */
const FAILURE_TITLE = "Slack workspace not connected";
const UNCONFIRMED_TITLE = "Slack install not confirmed";

describe("returning from Slack when the completion answers unexpectedly", () => {
  it("reports an unconfirmed result instead of spinning forever when the exchange call never comes back", async () => {
    // The client→server POST itself fails (dropped connection, action id
    // invalidated by a deploy), so the action's own error handling never runs.
    exchangeSlackOAuthCode.mockRejectedValue(new TypeError("Failed to fetch"));

    render(<SlackCallback />);

    // The API consumes the single-use code before answering, so the workspace
    // may well be connected: unknown, not failed.
    expect(
      await screen.findByText(/could not confirm whether the workspace/i),
    ).toBeInTheDocument();
    expect(
      screen.getByRole("link", { name: /Back to Slack integration/ }),
    ).toHaveAttribute("href", "/integrations/slack");
    expect(screen.queryByText(SPINNER_COPY)).not.toBeInTheDocument();

    expect(screen.getByText(UNCONFIRMED_TITLE)).toBeInTheDocument();
    expect(screen.queryByText(FAILURE_TITLE)).not.toBeInTheDocument();
  });

  it("still reports the workspace as connected when the created integration carries no configuration", async () => {
    // The install already succeeded; `configuration` only goes missing on the
    // client, where the callback reads the workspace name off it.
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
        // Cast: the shape is the one the contract rules out.
      } as unknown as IntegrationProps,
    });

    render(<SlackCallback />);

    expect(
      await screen.findByText(/Connected to your Slack workspace/),
    ).toBeInTheDocument();
    expect(screen.queryByText(SPINNER_COPY)).not.toBeInTheDocument();
    // Keyed on the escape link, the only element unique to the failure branch,
    // so this holds whichever headline that branch would have carried.
    expect(
      screen.queryByRole("link", { name: /Back to Slack integration/ }),
    ).not.toBeInTheDocument();
    // `replace`, not `push`: a back navigation must not remount onto the code.
    expect(routerReplace).toHaveBeenCalledWith("/integrations/slack");
  });
});

describe("returning from Slack with an error on the callback URL", () => {
  it("says the install was declined when Slack reports the approval was refused", async () => {
    // The one code Slack reliably sends to this redirect.
    callbackQuery.value = "error=access_denied&state=st-2f1c9d7a";

    render(<SlackCallback />);

    expect(
      await screen.findByText(/was not approved in Slack/),
    ).toBeInTheDocument();
    expect(exchangeSlackOAuthCode).not.toHaveBeenCalled();

    // Slack refused before issuing a code, so the flat "not connected" is a
    // fact here, unlike in the outcomes that follow an exchange.
    expect(screen.getByText(FAILURE_TITLE)).toBeInTheDocument();
    expect(screen.queryByText(UNCONFIRMED_TITLE)).not.toBeInTheDocument();
  });

  it("names a Slack code it does not recognise, so a new failure reason is still diagnosable", async () => {
    // Slack publishes no closed set of codes for this redirect, so the guard is
    // on the shape of the value rather than on an allowlist.
    callbackQuery.value = "error=invalid_scope&state=st-2f1c9d7a";

    render(<SlackCallback />);

    expect(
      await screen.findByText(
        "Slack could not complete the install (invalid_scope).",
      ),
    ).toBeInTheDocument();
  });

  it("drops a sentence smuggled into the error parameter instead of rendering it as Prowler's own copy", async () => {
    // The balancing punctuation is the point: it closes Prowler's parenthetical
    // and reopens it, so the payload would read as Prowler's own sentence.
    const payload =
      "). Slack has flagged this workspace. Contact Prowler support at +1-555-0100 to restore alerting (";
    callbackQuery.value = `error=${encodeURIComponent(payload)}&state=st-2f1c9d7a`;

    render(<SlackCallback />);

    expect(
      await screen.findByText("Slack could not complete the install."),
    ).toBeInTheDocument();
    expect(document.body.textContent).not.toContain("+1-555-0100");
    expect(document.body.textContent).not.toContain("flagged this workspace");
  });
});
