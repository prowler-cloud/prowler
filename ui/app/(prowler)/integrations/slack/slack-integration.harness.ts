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
import { setSlackDefaultChannel } from "@/actions/integrations/slack";
import { SlackCallback } from "@/components/integrations/slack/slack-callback";

import { IntegrationsContent } from "../integrations-content";

import { SlackIntegrationContent } from "./slack-integration-content";

export const CONNECTION_OUTCOME = {
  SUCCESS: "success",
  FAILURE: "failure",
} as const;

export type ConnectionOutcome =
  (typeof CONNECTION_OUTCOME)[keyof typeof CONNECTION_OUTCOME];

/** Sentinel: the page settled on "no channel recorded", rather than not yet. */
const NO_DEFAULT_CHANNEL = "<no channel recorded>";

export const REVOCATION_OUTCOME = {
  REVOKED: "revoked",
  NOT_REVOKED: "not-revoked",
  /** The answer said nothing either way, so the page claims neither. */
  UNREPORTED: "unreported",
} as const;

export type RevocationOutcome =
  (typeof REVOCATION_OUTCOME)[keyof typeof REVOCATION_OUTCOME];

/** The alert shown when Slack never confirmed the revocation. */
const REVOCATION_NOTICE = /revocation/i;

/** The alert shown when Slack has stopped accepting the credential. */
const REVOKED_CREDENTIAL_NOTICE = /no longer accepts Prowler's access/;

interface CallbackParams {
  code?: string;
  state?: string;
  /** Slack's own refusal code, e.g. `access_denied`. */
  error?: string;
}

/** What a picker search leaves on offer. */
interface ChannelSearch {
  /** Names still offered once the filter landed, in the order offered. */
  offered: string[];
  /** The picker's no-match note; null while any channel is still offered. */
  emptyNote: string | null;
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

    const readsBefore = this.channelListCallCount;
    this.mounted = render(await SlackIntegrationContent());
    if (this.fixture.install) await this.waitForChannelsRead(readsBefore);
  }

  private mounted: ReturnType<typeof render> | null = null;

  /**
   * Open the management page again, the way a later visit does — the handlers in
   * place keep serving what the previous visit left behind. Unmounts the previous
   * render first: two live copies would make every assertion ambiguous.
   */
  async revisit(): Promise<void> {
    (await this.mounted)?.unmount();
    const readsBefore = this.channelListCallCount;
    this.mounted = render(await SlackIntegrationContent());
    await this.mounted;
    if (this.fixture.install) await this.waitForChannelsRead(readsBefore);
  }

  /**
   * Refresh the page's server data under the open card, as `revalidatePath` does
   * after an action: new props, no unmount, so React state survives — unlike
   * `revisit()`, which re-seeds everything from scratch.
   */
  async refreshPageData(): Promise<void> {
    const rendered = await this.mounted;
    if (!rendered) {
      throw new Error("refreshPageData: the page is not mounted");
    }
    await rendered.rerender(await SlackIntegrationContent());
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

  async offersConnectionTest(): Promise<boolean> {
    const button = await this.waitFor(
      () => this.buttonByText(/Test connection/),
      5000,
      "the Test connection button",
    );
    return !button.disabled;
  }

  /**
   * Why the check cannot run, read from the copy the button points at: a reason
   * found anywhere else on the page never reaches whoever sees the control.
   */
  connectionCheckBlockedReason(): string | null {
    const button = this.buttonByText(/Test connection/);
    const describedBy = button?.getAttribute("aria-describedby");
    if (!describedBy) return null;

    const reason = this.container.querySelector<HTMLElement>(`#${describedBy}`);
    return reason ? (reason.textContent ?? "").trim() : null;
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

  get connectionCheckCallCount(): number {
    return this.countRequests("POST", "/connection");
  }

  /** The outcome of a check under way, started by the button or by a save. */
  async connectionOutcome(): Promise<ConnectionOutcome> {
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

  async testConnection(): Promise<ConnectionOutcome> {
    await this.clickButton(/Test connection/);

    return this.connectionOutcome();
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

  // --- Choosing a destination channel --------------------------------------

  /** Channel reads issued — one per cursor page the UI followed. */
  get channelListCallCount(): number {
    return this.countRequests("GET", "/slack/channels");
  }

  /**
   * Wait for the channel read every connected mount starts, counting from the
   * reads already issued: one still in flight when the test ends lands in the
   * middle of the next, against a harness that never asked for it.
   */
  private async waitForChannelsRead(readsBefore: number): Promise<void> {
    await this.waitFor(
      () => {
        const refresh = this.buttonByText(/Refresh channels/);
        return this.channelListCallCount > readsBefore &&
          refresh !== null &&
          !refresh.disabled
          ? true
          : null;
      },
      15000,
      "the workspace's channels to be read",
    );
  }

  /**
   * Open the picker and hand back its options. A re-render landing mid-gesture
   * makes Radix drop the open state, so re-open from the keyboard when nothing
   * mounted at all.
   */
  private async openChannelPicker(): Promise<HTMLElement[]> {
    const mounted = (): HTMLElement[] | null => {
      const options = Array.from(
        document.querySelectorAll<HTMLElement>('[role="option"]'),
      );
      return options.length > 0 ? options : null;
    };

    const alreadyOpen = mounted();
    if (alreadyOpen) return alreadyOpen;

    const trigger = await this.waitFor<HTMLElement>(
      () => this.q("#slack-channel"),
      10000,
      "the channel picker",
    );

    await this.clickElement(trigger, { fallbackToDomClick: true });

    let options = await this.waitForOrNull(
      mounted,
      2000,
      "the channel options",
    );
    if (!options) {
      await this.user.keyboard("{Enter}");
      options = await this.waitForOrNull(mounted, 8000, "the channel options");
    }

    if (!options) {
      throw new Error("openChannelPicker: the channel picker offered nothing");
    }
    return options;
  }

  private async closeChannelPicker(): Promise<void> {
    await this.user.keyboard("{Escape}");
    await this.waitForTransition();
  }

  /**
   * Re-read the workspace's channels, the way a user does after inviting
   * `@Prowler` to one in Slack. Waits for the read to have settled, not for the
   * click alone.
   */
  async refreshChannels(): Promise<void> {
    const readsBefore = this.channelListCallCount;
    await this.clickButton(/Refresh channels/);

    await this.waitFor(
      () => {
        const button = this.buttonByText(/Refresh channels/);
        return (
          this.channelListCallCount > readsBefore &&
          button !== null &&
          !button.disabled
        );
      },
      15000,
      "the workspace's channels to be read again",
    );
  }

  /** The channels the workspace offers, in the order the picker lists them. */
  async channelOptions(): Promise<string[]> {
    const options = await this.openChannelPicker();
    const names = options.map(
      (option) => option.getAttribute("data-channel") ?? "",
    );

    await this.closeChannelPicker();

    return names;
  }

  /**
   * Whether the channel offered under `name` is presented as private — read
   * from the marker the user sees, not from how the option is wired up.
   */
  async isChannelShownAsPrivate(name: string): Promise<boolean> {
    const options = await this.openChannelPicker();
    const option = options.find(
      (element) => element.getAttribute("data-channel") === name,
    );

    await this.closeChannelPicker();

    return /Private/.test(option?.textContent ?? "");
  }

  /**
   * Open the picker, type `query` into its search, and hand back what the
   * filter leaves on offer. The search dies with the popover, so each call
   * starts from the full list.
   */
  async searchChannels(query: string): Promise<ChannelSearch> {
    const all = await this.openChannelPicker();

    const input = document.querySelector<HTMLInputElement>("[cmdk-input]");
    if (!input) {
      throw new Error("searchChannels: the open picker has no search field");
    }
    await this.user.fill(input, query);

    // The filter lands a render after the last keystroke: the offered set
    // shrinks, or the no-match note shows. A query that matches everything
    // would never settle — the tests only narrow.
    await this.waitFor(
      () =>
        document.querySelectorAll('[role="option"]').length !== all.length ||
        document.querySelector("[cmdk-empty]") !== null ||
        null,
      5000,
      "the search to narrow the channels",
    );

    const offered = Array.from(
      document.querySelectorAll<HTMLElement>('[role="option"]'),
    ).map((option) => option.getAttribute("data-channel") ?? "");
    const emptyNote =
      document.querySelector<HTMLElement>("[cmdk-empty]")?.textContent ?? null;

    await this.closeChannelPicker();

    return { offered, emptyNote };
  }

  private async pickAndSave(name: string): Promise<void> {
    const options = await this.openChannelPicker();
    const option = options.find(
      (element) => element.getAttribute("data-channel") === name,
    );

    if (!option) {
      throw new Error(`pickAndSave: no channel named "${name}" is offered`);
    }

    await this.user.click(option);
    await this.waitForTransition();
    await this.clickButton(/Save channel/);
  }

  /** Pick a channel, save it, and wait for it to be recorded as the destination. */
  async chooseChannel(name: string): Promise<void> {
    await this.pickAndSave(name);
    await this.waitFor(
      () => this.defaultChannelName() === name,
      15000,
      `#${name} to be recorded as the destination`,
    );
  }

  /**
   * Record a different destination away from this page — a second tab, or someone
   * else in the tenant. Goes through the same call the page makes, leaving this
   * page's own copy of it untouched.
   */
  async channelRecordedElsewhere(name: string): Promise<void> {
    const channel = this.fixture.channels.find((c) => c.name === name);
    if (!channel) {
      throw new Error(
        `channelRecordedElsewhere: no channel named "${name}" is offered`,
      );
    }

    const integrationId = this.fixture.install?.id;
    if (!integrationId) {
      throw new Error("channelRecordedElsewhere: no workspace is connected");
    }

    const result = await setSlackDefaultChannel(integrationId, channel.id);
    if ("error" in result) {
      throw new Error(`channelRecordedElsewhere: ${result.error}`);
    }
  }

  /** Whether the picked channel can be saved — false when there is nothing new to save. */
  offersChannelSave(): boolean {
    const button = this.buttonByText(/Save channel/);
    return button !== null && !button.disabled;
  }

  /**
   * Try to save a channel the API refuses and hand back what the user is told. A
   * save that succeeds fails the test rather than timing out.
   */
  async refusedChannelSave(name: string): Promise<string> {
    await this.pickAndSave(name);

    return this.waitFor(
      () => {
        if (this.defaultChannelName() === name) {
          throw new Error(
            `refusedChannelSave: #${name} was recorded, not refused`,
          );
        }
        return this.toastText(/Could not save the destination channel/);
      },
      15000,
      "the refused channel save",
    );
  }

  /**
   * The text of the toast matching `pattern` — title and message together. Radix
   * portals each toast into its viewport as an `<li>`, outside the page's markup.
   */
  private toastText(pattern: RegExp): string | null {
    const toast = Array.from(
      document.querySelectorAll<HTMLElement>("ol li"),
    ).find((element) => pattern.test(element.textContent ?? ""));
    return toast ? (toast.textContent ?? "").replace(/\s+/g, " ").trim() : null;
  }

  private defaultChannelName(): string | null {
    return (
      /Prowler posts to #(\S+?)\./.exec(
        this.container.textContent ?? "",
      )?.[1] ?? null
    );
  }

  /** The channel recorded as the integration's destination, if any. */
  async defaultChannel(): Promise<string | null> {
    const settled = await this.waitFor(
      () =>
        this.defaultChannelName() ??
        (this.containsText(/No destination channel recorded yet/)
          ? NO_DEFAULT_CHANNEL
          : null),
      10000,
      "the recorded destination channel",
    );
    return settled === NO_DEFAULT_CHANNEL ? null : settled;
  }

  /** What the user is told when the workspace exposes no channel at all. */
  async channelPickerMessage(): Promise<string> {
    const alert = await this.waitFor(
      () =>
        Array.from(
          this.container.querySelectorAll<HTMLElement>('[data-slot="alert"]'),
        ).find((element) =>
          /No channels available yet|Could not read the workspace/.test(
            element.textContent ?? "",
          ),
        ),
      10000,
      "the channel picker's message",
    );
    return (alert.textContent ?? "").replace(/\s+/g, " ").trim();
  }

  /**
   * What the user is told about a list short of the workspace, shown beside a
   * picker that still works — unlike `channelPickerMessage()`, which replaces it.
   */
  partialListNotice(): string | null {
    const notice = this.q("[data-channels-notice]");
    return notice
      ? (notice.textContent ?? "").replace(/\s+/g, " ").trim()
      : null;
  }

  /** Whether the picker was replaced by the "could not read them" alert. */
  saysChannelsUnreadable(): boolean {
    return this.containsText(/Could not read the workspace/);
  }

  /** The invite copy that says how to make a private channel appear. */
  channelInviteHint(): string | null {
    const hint = Array.from(
      this.container.querySelectorAll<HTMLElement>("p"),
    ).find((element) => /invites? @Prowler/.test(element.textContent ?? ""));
    return hint ? (hint.textContent ?? "").trim() : null;
  }

  // --- Disconnecting ------------------------------------------------------

  get disconnectCallCount(): number {
    return this.countRequests("DELETE", "/integrations/");
  }

  /**
   * Disconnects the workspace, confirming the way a user has to, and reports
   * what the page says about the revocation. The outcomes are mutually
   * exclusive, so asking for one also checks the others are absent.
   *
   * The revoked and unreported outcomes share a toast title, so each is read
   * from its own description: a title match would agree with either.
   */
  async disconnect(): Promise<RevocationOutcome> {
    await this.openDisconnectConfirmation();
    return this.confirmDisconnect();
  }

  /**
   * Opens the confirmation and reports what it asks the user to accept, before
   * anything is accepted.
   */
  async openDisconnectConfirmation(): Promise<string> {
    // The dialog's own button carries the noun too, hence the exact match on
    // the card's action.
    await this.clickButton(/^\s*Disconnect\s*$/);

    const description = await this.waitFor(
      () => this.q('[data-slot="dialog-description"]'),
      10000,
      "the disconnect confirmation",
    );
    return (description.textContent ?? "").replace(/\s+/g, " ").trim();
  }

  /** Accepts the open confirmation and reports the revocation outcome. */
  async confirmDisconnect(): Promise<RevocationOutcome> {
    await this.clickButton(/Disconnect workspace/);

    return this.waitFor(
      () => {
        const outcomes = [
          this.alertMatching(REVOCATION_NOTICE)
            ? REVOCATION_OUTCOME.NOT_REVOKED
            : null,
          this.containsText(/has been revoked/)
            ? REVOCATION_OUTCOME.REVOKED
            : null,
          this.containsText(/is no longer connected to Prowler/)
            ? REVOCATION_OUTCOME.UNREPORTED
            : null,
        ].filter((outcome): outcome is RevocationOutcome => outcome !== null);

        if (outcomes.length > 1) {
          throw new Error(
            `confirmDisconnect: the page shows ${outcomes.join(" and ")} at once`,
          );
        }
        return outcomes[0] ?? null;
      },
      15000,
      "the disconnect outcome",
    );
  }

  /**
   * Try a disconnect the API refuses and hand back what the user is told. One
   * that goes through fails the test rather than timing out.
   */
  async refusedDisconnect(): Promise<string> {
    await this.openDisconnectConfirmation();
    await this.clickButton(/Disconnect workspace/);

    return this.waitFor(
      () => {
        if (this.containsText(/No workspace connected/)) {
          throw new Error(
            "refusedDisconnect: the workspace was disconnected, not refused",
          );
        }
        return this.toastText(/Disconnect failed/);
      },
      15000,
      "the refused disconnect",
    );
  }

  /**
   * Whether the page is back to offering an install with no workspace
   * connected. The consent URL is minted after the disconnect, so the install
   * affordance appears a beat after the copy does.
   */
  async returnedToUnconnectedState(): Promise<boolean> {
    await this.waitForText(/No workspace connected/, 10000);
    return (
      (await this.waitForOrNull(
        () => this.offersInstall(),
        5000,
        "the install to be offered again",
      )) ?? false
    );
  }

  /** Whether the page is asking the user to remove the access in Slack. */
  showsRevocationNotice(): boolean {
    return this.alertMatching(REVOCATION_NOTICE) !== null;
  }

  /**
   * What the user is told when the row was removed but Slack never confirmed
   * the revocation.
   */
  async revocationNotice(): Promise<string> {
    const notice = await this.waitFor(
      () => this.alertMatching(REVOCATION_NOTICE),
      10000,
      "the revocation notice",
    );
    return (notice.textContent ?? "").trim();
  }

  // --- A credential Slack no longer accepts --------------------------------

  /** What the user is told when Slack has stopped accepting the credential. */
  async revokedCredentialNotice(): Promise<string> {
    const notice = await this.waitFor(
      () => this.alertMatching(REVOKED_CREDENTIAL_NOTICE),
      10000,
      "the revoked-credential notice",
    );
    return (notice.textContent ?? "").replace(/\s+/g, " ").trim();
  }

  /** Whether the page is saying Slack has stopped accepting the credential. */
  showsRevokedCredentialNotice(): boolean {
    return this.alertMatching(REVOKED_CREDENTIAL_NOTICE) !== null;
  }

  private reconnectLink(): HTMLAnchorElement | null {
    return (
      Array.from(this.container.querySelectorAll("a")).find((anchor) =>
        /Reconnect to Slack/.test(anchor.textContent ?? ""),
      ) ?? null
    );
  }

  /** Whether the page offers to approve Prowler in the workspace again. */
  offersReconnect(): boolean {
    return this.reconnectLink() !== null;
  }

  /**
   * Waits, unlike `offersReconnect`: the affordance needs a consent URL the
   * page mints only once it knows it needs one, so it lands a beat after the
   * notice that explains it.
   */
  async waitForReconnect(): Promise<void> {
    await this.waitFor(() => this.reconnectLink(), 10000, "the reconnect link");
  }

  /** The consent URL the reconnect affordance points at, once it is offered. */
  async reconnectUrl(): Promise<string> {
    const link = await this.waitFor(
      () => this.reconnectLink(),
      10000,
      "the reconnect link",
    );
    return link.href;
  }

  /** The alert whose text matches, of however many the page is showing. */
  private alertMatching(pattern: RegExp): HTMLElement | null {
    return (
      Array.from(
        this.container.querySelectorAll<HTMLElement>('[data-slot="alert"]'),
      ).find((alert) => pattern.test(alert.textContent ?? "")) ?? null
    );
  }
}
