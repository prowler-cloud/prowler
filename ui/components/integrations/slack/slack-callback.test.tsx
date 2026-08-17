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
import { describe, expect, it, vi } from "vitest";

import type { IntegrationProps } from "@/types/integrations";

import { SlackCallback } from "./slack-callback";

const { exchangeSlackOAuthCode } = vi.hoisted(() => ({
  exchangeSlackOAuthCode: vi.fn(),
}));

vi.mock("@/actions/integrations/slack", () => ({ exchangeSlackOAuthCode }));

vi.mock("next/navigation", () => ({
  useRouter: () => ({ replace: vi.fn() }),
  useSearchParams: () =>
    new URLSearchParams("code=slack-code-1f4a&state=st-2f1c9d7a"),
}));

const SPINNER_COPY = /Connecting your Slack workspace/;

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
    expect(
      screen.queryByText(/Slack workspace not connected/),
    ).not.toBeInTheDocument();
  });
});
