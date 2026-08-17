/**
 * Page-level test harness for the Slack integration (Vitest Browser Mode).
 *
 * Owns mounting and MSW wiring for the real pages the flow touches — the
 * integrations catalogue Slack is listed on, the management page and the OAuth
 * callback — and exposes Slack vocabulary ("connect", "the connected
 * workspace", "test the connection") so the tests never reach for a selector.
 * The DOM and wait primitives stay `protected` in `BrowserHarness`.
 *
 * Every mount renders production's own components: the async server component
 * that loads the install, and the client components the callback and the
 * catalogue pages render. A client renderer cannot render an async component,
 * so it is called and its returned element is what gets rendered — the same
 * trick the providers harness uses.
 */

import { createElement } from "react";

import { BrowserHarness } from "@/__tests__/browser-harness";
import { handlersForSlack } from "@/__tests__/msw/handlers/slack";
import type { SlackFixture } from "@/__tests__/msw/handlers/slack.fixtures";
import { worker } from "@/__tests__/msw/worker";
import { render } from "@/__tests__/render-browser";
import { SlackCallback } from "@/components/integrations/slack/slack-callback";

import { IntegrationsContent } from "../integrations-content";

import { SlackIntegrationContent } from "./slack-integration-content";

export const CONNECTION_OUTCOME = {
  SUCCESS: "success",
  FAILURE: "failure",
} as const;

export type ConnectionOutcome =
  (typeof CONNECTION_OUTCOME)[keyof typeof CONNECTION_OUTCOME];

/** What Slack put on the callback URL when it sent the user back. */
interface CallbackParams {
  code?: string;
  state?: string;
  /** Slack's own refusal, e.g. `access_denied` when the user declined. */
  error?: string;
}

export class SlackIntegrationHarness extends BrowserHarness<SlackFixture> {
  /** Exchanges issued — the callback's once-guard is what keeps this at 1. */
  get exchangeCallCount(): number {
    return this.countRequests("POST", "/slack/oauth/exchange");
  }

  get authorizeUrlCallCount(): number {
    return this.countRequests("POST", "/slack/oauth/authorize-url");
  }

  // --- Mounting -----------------------------------------------------------

  private wireHandlers(): void {
    worker.use(...handlersForSlack(this.fixture));
    this.trackRequests(worker);
  }

  /** Mount the Slack management page at `/integrations/slack`. */
  async mount(): Promise<void> {
    window.history.replaceState(null, "", "/integrations/slack");
    this.wireHandlers();

    render(await SlackIntegrationContent());
  }

  /** Mount the OAuth callback with the query string Slack redirected to. */
  async mountCallback({ code, state, error }: CallbackParams): Promise<void> {
    const params = new URLSearchParams();
    if (code) params.set("code", code);
    if (state) params.set("state", state);
    if (error) params.set("error", error);
    window.history.replaceState(
      null,
      "",
      `/integrations/slack/callback?${params.toString()}`,
    );
    this.wireHandlers();

    render(createElement(SlackCallback));
  }

  /**
   * Mount the integrations catalogue at `/integrations` — the page Slack is
   * listed on. No handlers are wired: every card there is static.
   */
  mountCatalogue(): void {
    window.history.replaceState(null, "", "/integrations");

    render(createElement(IntegrationsContent));
  }

  // --- The integrations catalogue ------------------------------------------

  /** The integrations the catalogue offers, by the name shown on each card. */
  async listedIntegrations(): Promise<string[]> {
    const headings = await this.waitFor(
      () => {
        const found = Array.from(
          this.container.querySelectorAll<HTMLElement>("h4"),
        );
        return found.length > 0 ? found : null;
      },
      5000,
      "the integrations catalogue",
    );
    return headings.map((heading) => (heading.textContent ?? "").trim());
  }

  /** Whether the catalogue offers a way into the Slack management page. */
  offersSlackManagement(): boolean {
    return this.q('a[href="/integrations/slack"]') !== null;
  }

  // --- Starting the install -----------------------------------------------

  private connectLink(): HTMLAnchorElement | null {
    return (
      Array.from(this.container.querySelectorAll("a")).find((anchor) =>
        /Add to Slack/.test(anchor.textContent ?? ""),
      ) ?? null
    );
  }

  /** The consent URL the install affordance points at, once it is offered. */
  async authorizeUrl(): Promise<string> {
    const link = await this.waitFor(
      () => this.connectLink(),
      5000,
      "the Add to Slack link",
    );
    return link.href;
  }

  /**
   * Start the install the way a user does, and report where Slack's consent
   * screen would have been reached at.
   *
   * The click is real — it goes through user-event, so a disabled or
   * unclickable affordance still fails the test — but its default action is
   * cancelled: following the link would navigate the test frame off the app.
   */
  async connect(): Promise<string> {
    const link = await this.waitFor(
      () => this.connectLink(),
      5000,
      "the Add to Slack link",
    );

    let destination = "";
    const intercept = (event: MouseEvent) => {
      event.preventDefault();
      destination = link.href;
    };
    link.addEventListener("click", intercept);
    try {
      await this.clickElement(link, { fallbackToDomClick: true });
    } finally {
      link.removeEventListener("click", intercept);
    }

    return destination;
  }

  /** Whether the install is offered at all (it is not without a Slack app). */
  offersInstall(): boolean {
    return this.connectLink() !== null;
  }

  async waitForUnavailable(): Promise<void> {
    await this.waitForText(/Slack is not available in this environment yet/);
  }

  /** Whether the page claims this deployment has no Slack app. */
  saysUnavailable(): boolean {
    return this.containsText(/Slack is not available in this environment yet/);
  }

  /** What the page says about Slack rate limiting Prowler, once it says it. */
  async rateLimitNotice(): Promise<string> {
    await this.waitForText(/Slack is busy right now/, 10000);
    const description = await this.waitFor(
      () => this.q('[data-slot="alert-description"]'),
      5000,
      "the rate limit notice",
    );
    return (description.textContent ?? "").trim();
  }

  /**
   * What the page says when the tenant's Slack install could not be read.
   *
   * Reaching this at all is part of the assertion: the read fails by throwing,
   * so a page that does not catch it never renders — the mount itself fails.
   */
  async loadErrorNotice(): Promise<string> {
    await this.waitForText(/Could not load your Slack integration/, 10000);
    const description = await this.waitFor(
      () => this.q('[data-slot="alert-description"]'),
      5000,
      "the load error notice",
    );
    return (description.textContent ?? "").trim();
  }

  // --- Connected state ----------------------------------------------------

  /**
   * The workspace the page reports as connected — on the management page and
   * on the callback alike.
   *
   * Read from the element that carries the heading, not from the page's text:
   * "Connected to <workspace>" runs straight into the copy that follows it in
   * `textContent`, so matching the whole page would report that copy as part of
   * the workspace's name.
   */
  async connectedWorkspaceName(): Promise<string> {
    const heading = await this.waitFor(
      () => this.deepestElementMatching(/^Connected to \S/),
      5000,
      "the connected workspace name",
    );
    return (heading.textContent ?? "").trim().replace(/^Connected to /, "");
  }

  /**
   * The most specific element whose own text matches: the last one in document
   * order, since every ancestor of a match matches too.
   */
  private deepestElementMatching(pattern: RegExp): HTMLElement | null {
    return (
      Array.from(this.container.querySelectorAll<HTMLElement>("*"))
        .reverse()
        .find((element) => pattern.test((element.textContent ?? "").trim())) ??
      null
    );
  }

  /**
   * How the page reports the connection, in the badge's own words.
   *
   * Read off the badge's own state attribute rather than by matching copy: the
   * heading right beside it starts "Connected to …", so a text search would
   * happily report the heading as the badge.
   */
  async connectionBadge(): Promise<string> {
    const badge = await this.waitFor(
      () => this.q("[data-connection-status]"),
      5000,
      "the connection badge",
    );
    return (badge.textContent ?? "").trim();
  }

  /** Whether the page offers a connection check the user can actually run. */
  async offersConnectionTest(): Promise<boolean> {
    const button = await this.waitFor(
      () => this.buttonByText(/Test connection/),
      5000,
      "the Test connection button",
    );
    return !button.disabled;
  }

  /** Whether the page names choosing a channel as what comes next. */
  saysChannelIsNextStep(): boolean {
    return this.containsText(/Choosing a destination channel is the next step/);
  }

  async testConnection(): Promise<ConnectionOutcome> {
    await this.clickButton(/Test connection/);

    return this.waitFor(
      () => {
        if (this.containsText(/Connection test successful/)) {
          return CONNECTION_OUTCOME.SUCCESS;
        }
        if (this.containsText(/Connection test failed/)) {
          return CONNECTION_OUTCOME.FAILURE;
        }
        return null;
      },
      15000,
      "the connection test outcome",
    );
  }

  // --- Returning from Slack -----------------------------------------------

  /** Whether the callback settled on a connected workspace. */
  async completedInstall(): Promise<boolean> {
    const outcome = await this.waitFor(
      () =>
        this.containsText(/Connected to /) ||
        this.containsText(/Slack workspace not connected/),
      10000,
      "the callback outcome",
    );
    return outcome && this.containsText(/Connected to /);
  }

  /** What the user is told when the install did not complete. */
  async installFailureReason(): Promise<string> {
    await this.waitForText(/Slack workspace not connected/, 10000);
    const description = await this.waitFor(
      () => this.q('[data-slot="alert-description"]'),
      5000,
      "the failure reason",
    );
    return (description.textContent ?? "").trim();
  }

  /** Whether the page offers a way back to try the install again. */
  offersRetry(): boolean {
    return (
      Array.from(this.container.querySelectorAll("a")).some(
        (anchor) =>
          anchor.getAttribute("href") === "/integrations/slack" &&
          /Back to Slack integration/.test(anchor.textContent ?? ""),
      ) || this.offersInstall()
    );
  }
}
