/**
 * Page-level test harness for the Slack integration (Vitest Browser Mode).
 *
 * A client renderer cannot render an async server component, so the component is
 * called and the element it returns is what gets rendered.
 */

import { revalidatePath } from "next/cache";
import { createElement } from "react";
import { vi } from "vitest";

import { BrowserHarness } from "@/__tests__/browser-harness";
import { handlersForSlack } from "@/__tests__/msw/handlers/slack";
import type { SlackFixture } from "@/__tests__/msw/handlers/slack.fixtures";
import { worker } from "@/__tests__/msw/worker";
import { render } from "@/__tests__/render-browser";
import { SlackCallback } from "@/components/integrations/slack/slack-callback";

import { IntegrationsContent } from "../integrations-content";

import { SlackIntegrationContent } from "./slack-integration-content";

interface CallbackParams {
  code?: string;
  state?: string;
  /** Slack's own refusal code, e.g. `access_denied`. */
  error?: string;
}

export class SlackIntegrationHarness extends BrowserHarness<SlackFixture> {
  get exchangeCallCount(): number {
    return this.countRequests("POST", "/slack/oauth/exchange");
  }

  get authorizeUrlCallCount(): number {
    return this.countRequests("POST", "/slack/oauth/authorize-url");
  }

  /** Paths the actions asked Next to refresh (`next/cache` is stubbed in this lane). */
  get revalidatedPaths(): string[] {
    return vi.mocked(revalidatePath).mock.calls.map(([path]) => path);
  }

  // --- Mounting -----------------------------------------------------------

  private wireHandlers(): void {
    // The stub is module-level and shared, so clearing it here is what makes
    // `revalidatedPaths` mean "since this mount".
    vi.mocked(revalidatePath).mockClear();
    worker.use(...handlersForSlack(this.fixture));
    this.trackRequests(worker);
  }

  async mount(): Promise<void> {
    window.history.replaceState(null, "", "/integrations/slack");
    this.wireHandlers();

    render(await SlackIntegrationContent());
  }

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

  /** Mount the integrations catalogue. No handlers: every card there is static. */
  mountCatalogue(): void {
    window.history.replaceState(null, "", "/integrations");

    render(createElement(IntegrationsContent));
  }

  // --- The integrations catalogue ------------------------------------------

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

  async authorizeUrl(): Promise<string> {
    const link = await this.waitFor(
      () => this.connectLink(),
      5000,
      "the Add to Slack link",
    );
    return link.href;
  }

  /**
   * Clicks the install affordance and reports where it points. The default
   * action is cancelled: following the link navigates the test frame off the app.
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

  offersInstall(): boolean {
    return this.connectLink() !== null;
  }

  async waitForUnavailable(): Promise<void> {
    await this.waitForText(/Slack is not available in this environment yet/);
  }

  saysUnavailable(): boolean {
    return this.containsText(/Slack is not available in this environment yet/);
  }

  saysLoadFailed(): boolean {
    return this.containsText(/Could not load your Slack integration/);
  }

  async rateLimitNotice(): Promise<string> {
    await this.waitForText(/Slack is busy right now/, 10000);
    const description = await this.waitFor(
      () => this.q('[data-slot="alert-description"]'),
      5000,
      "the rate limit notice",
    );
    return (description.textContent ?? "").trim();
  }

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
   * Read from the heading element, not the page text: in `textContent`
   * "Connected to <workspace>" runs straight into the copy that follows it.
   */
  async connectedWorkspaceName(): Promise<string> {
    const heading = await this.waitFor(
      () => this.deepestElementMatching(/^Connected to \S/),
      5000,
      "the connected workspace name",
    );
    return (heading.textContent ?? "").trim().replace(/^Connected to /, "");
  }

  /** Last match in document order: every ancestor of a match matches too. */
  private deepestElementMatching(pattern: RegExp): HTMLElement | null {
    return (
      Array.from(this.container.querySelectorAll<HTMLElement>("*"))
        .reverse()
        .find((element) => pattern.test((element.textContent ?? "").trim())) ??
      null
    );
  }

  /**
   * Keyed on the badge's state attribute, not its copy: the heading beside it
   * also starts "Connected to …".
   */
  async connectionBadge(): Promise<string> {
    const badge = await this.waitFor(
      () => this.q("[data-connection-status]"),
      5000,
      "the connection badge",
    );
    return (badge.textContent ?? "").trim();
  }

  /** Absent, or there but disabled: both read as "not offered". */
  offersConnectionTest(): boolean {
    const button = this.buttonByText(/Test connection/);
    return button !== null && !button.disabled;
  }

  saysChannelIsNextStep(): boolean {
    return this.containsText(/Choosing a destination channel is the next step/);
  }

  /**
   * The "last checked" line as rendered, or null when the page shows none —
   * which is what a workspace whose connection was never checked shows.
   */
  lastCheckedLine(): string | null {
    const line = Array.from(
      this.container.querySelectorAll<HTMLElement>("p"),
    ).find((p) => /^Last checked:/.test((p.textContent ?? "").trim()));
    return line ? (line.textContent ?? "").trim() : null;
  }

  // --- Returning from Slack -----------------------------------------------

  /**
   * The one element every non-success outcome renders. Keyed on it rather than
   * the alert title, which is not the same claim on every outcome.
   */
  private backLink(): HTMLAnchorElement | null {
    return (
      Array.from(this.container.querySelectorAll("a")).find(
        (anchor) =>
          anchor.getAttribute("href") === "/integrations/slack" &&
          /Back to Slack integration/.test(anchor.textContent ?? ""),
      ) ?? null
    );
  }

  async completedInstall(): Promise<boolean> {
    const outcome = await this.waitFor(
      () => this.containsText(/Connected to /) || this.backLink() !== null,
      10000,
      "the callback outcome",
    );
    return outcome && this.containsText(/Connected to /);
  }

  async installFailureReason(): Promise<string> {
    await this.waitFor(() => this.backLink(), 10000, "the failed callback");
    const description = await this.waitFor(
      () => this.q('[data-slot="alert-description"]'),
      5000,
      "the failure reason",
    );
    return (description.textContent ?? "").trim();
  }

  async installFailureTitle(): Promise<string> {
    await this.waitFor(() => this.backLink(), 10000, "the failed callback");
    const title = await this.waitFor(
      () => this.q('[data-slot="alert-title"]'),
      5000,
      "the failure title",
    );
    return (title.textContent ?? "").trim();
  }

  offersRetry(): boolean {
    return this.backLink() !== null || this.offersInstall();
  }
}
