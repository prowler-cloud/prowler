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
import { setSlackAuthorizedChannels } from "@/actions/integrations/slack";

import { IntegrationsContent } from "../integrations-content";

import { SlackIntegrationContent } from "./slack-integration-content";

export const CONNECTION_OUTCOME = {
  SUCCESS: "success",
  FAILURE: "failure",
} as const;

export type ConnectionOutcome =
  (typeof CONNECTION_OUTCOME)[keyof typeof CONNECTION_OUTCOME];

/** Sentinel: the page settled on "no channels authorized", rather than not yet. */
const NO_AUTHORIZED_CHANNELS = "<no channels authorized>";

interface ChannelChip {
  name: string;
  isPrivate: boolean;
}

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

  /**
   * Open the integration page the way the OAuth callback route's redirect
   * does: with the outcome it wrote in the query string. The route handler
   * itself cannot run in this lane, so its side of the contract is covered by
   * `callback/route.test.ts`.
   */
  async mountAfterReturnFromSlack(
    params: Record<string, string>,
  ): Promise<void> {
    // Unmount first, or two copies of the page answer every query.
    (await this.mounted)?.unmount();
    window.history.replaceState(
      null,
      "",
      `/integrations/slack?${new URLSearchParams(params).toString()}`,
    );
    this.wireHandlers();

    const readsBefore = this.channelListCallCount;
    this.mounted = render(await SlackIntegrationContent());
    if (this.fixture.install) await this.waitForChannelsRead(readsBefore);
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

  /** The same copy, waited for: it follows data that lands after the action. */
  async connectionCheckHintMatching(pattern: RegExp): Promise<string> {
    return this.waitFor(
      () => {
        const hint = this.connectionCheckHint();
        return hint && pattern.test(hint) ? hint : null;
      },
      10000,
      `the connection check hint to match ${pattern}`,
    );
  }

  /**
   * What the check does — or why it cannot run — read from the copy the button
   * points at: a reason found anywhere else on the page never reaches whoever
   * sees the control.
   */
  connectionCheckHint(): string | null {
    const button = this.buttonByText(/Test connection/);
    const describedBy = button?.getAttribute("aria-describedby");
    if (!describedBy) return null;

    const reason = this.container.querySelector<HTMLElement>(`#${describedBy}`);
    return reason ? (reason.textContent ?? "").trim() : null;
  }

  async connectionFailureToast(): Promise<string> {
    return this.waitFor(
      () => this.toastText(/Connection test failed/),
      15000,
      "the connection failure toast",
    );
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

  private connectNotice(): HTMLElement | null {
    return this.q("[data-slack-connect-notice]");
  }

  /** Whether the page shows a callback outcome at all. Does not wait. */
  hasConnectNotice(): boolean {
    return this.connectNotice() !== null;
  }

  async connectNoticeTitle(): Promise<string> {
    const title = await this.waitFor(
      () => this.q('[data-slack-connect-notice] [data-slot="alert-title"]'),
      10000,
      "the connect notice title",
    );
    return (title.textContent ?? "").trim();
  }

  async connectNoticeDescription(): Promise<string> {
    const description = await this.waitFor(
      () =>
        this.q('[data-slack-connect-notice] [data-slot="alert-description"]'),
      10000,
      "the connect notice description",
    );
    return (description.textContent ?? "").trim();
  }

  /**
   * The query string once the notice's own URL cleanup has landed. Waits on
   * the `slack*` params being gone, so an assertion never reads mid-strip.
   */
  async strippedQuery(): Promise<string> {
    const settled = await this.waitFor(
      () => {
        const current = window.location.search;
        return current.includes("slack") ? null : current || "<none>";
      },
      5000,
      "the slack params to be stripped from the URL",
    );
    return settled === "<none>" ? "" : settled;
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
   * Scoped to the popover: the multi-select keeps a hidden mirror of its items
   * that exists with the listing closed, so a bare `[role="option"]` matches it.
   */
  private openPickerOptions(): HTMLElement[] | null {
    const options = Array.from(
      document.querySelectorAll<HTMLElement>(
        '[data-slot="multiselect-content"] [role="option"]',
      ),
    );
    return options.length > 0 ? options : null;
  }

  /**
   * Open the picker and hand back its options. A re-render landing mid-gesture
   * makes Radix drop the open state, so re-open from the keyboard when nothing
   * mounted at all.
   */
  private async openChannelPicker(): Promise<HTMLElement[]> {
    const alreadyOpen = this.openPickerOptions();
    if (alreadyOpen) return alreadyOpen;

    const trigger = await this.waitFor<HTMLElement>(
      () => this.q("#slack-channels"),
      10000,
      "the channel picker",
    );

    await this.clickElement(trigger, { fallbackToDomClick: true });

    let options = await this.waitForOrNull(
      () => this.openPickerOptions(),
      2000,
      "the channel options",
    );
    if (!options) {
      await this.user.keyboard("{Enter}");
      options = await this.waitForOrNull(
        () => this.openPickerOptions(),
        8000,
        "the channel options",
      );
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
        (this.openPickerOptions() ?? []).length !== all.length ||
        document.querySelector(
          '[data-slot="multiselect-content"] [cmdk-empty]',
        ) !== null ||
        null,
      5000,
      "the search to narrow the channels",
    );

    const offered = (this.openPickerOptions() ?? []).map(
      (option) => option.getAttribute("data-channel") ?? "",
    );
    const emptyNote =
      document.querySelector<HTMLElement>(
        '[data-slot="multiselect-content"] [cmdk-empty]',
      )?.textContent ?? null;

    await this.closeChannelPicker();

    return { offered, emptyNote };
  }

  private async pickChannels(names: string[]): Promise<void> {
    for (const name of names) {
      const options = await this.openChannelPicker();
      const option = options.find(
        (element) => element.getAttribute("data-channel") === name,
      );

      if (!option) {
        throw new Error(`pickChannels: no channel named "${name}" is offered`);
      }

      await this.user.click(option);
      await this.waitForTransition();
    }
    await this.closeChannelPicker();
  }

  /** Toggle the named channels without saving: the picks stay buffered. */
  async chooseChannels(names: string[]): Promise<void> {
    await this.pickChannels(names);
  }

  async saveChannels(): Promise<void> {
    await this.clickButton(/Save channels/);
  }

  /** What the page says before a save that drops channels (design D11). */
  deauthorizationWarning(): string | null {
    const warning = this.q("[data-deauthorize-warning]");
    return warning
      ? (warning.textContent ?? "").replace(/\s+/g, " ").trim()
      : null;
  }

  /** Drop the named channels, save, and wait until each is off the record. */
  async deauthorizeChannels(names: string[]): Promise<void> {
    await this.pickChannels(names);
    await this.saveChannels();
    await this.waitFor(
      () => {
        const authorized = this.authorizedChannelNames();
        const settled =
          authorized ??
          (this.containsText(/No destination channels authorized yet/)
            ? []
            : null);
        return settled && names.every((name) => !settled.includes(name))
          ? true
          : null;
      },
      15000,
      `${names.map((name) => `#${name}`).join(", ")} to be de-authorized`,
    );
  }

  /** Toggle the named channels, save, and wait until each is recorded. */
  async authorizeChannels(names: string[]): Promise<void> {
    await this.pickChannels(names);
    await this.saveChannels();
    await this.waitFor(
      () => {
        const authorized = this.authorizedChannelNames();
        return authorized && names.every((name) => authorized.includes(name))
          ? true
          : null;
      },
      15000,
      `${names.map((name) => `#${name}`).join(", ")} to be authorized`,
    );
  }

  /**
   * Authorize a different set away from this page — a second tab, or someone
   * else in the tenant. Goes through the same call the page makes, leaving this
   * page's own copy of it untouched.
   */
  async channelsRecordedElsewhere(names: string[]): Promise<void> {
    const channels = names.map((name) => {
      const channel = this.fixture.channels.find((c) => c.name === name);
      if (!channel) {
        throw new Error(
          `channelsRecordedElsewhere: no channel named "${name}" is offered`,
        );
      }
      return channel;
    });

    const integrationId = this.fixture.install?.id;
    if (!integrationId) {
      throw new Error("channelsRecordedElsewhere: no workspace is connected");
    }

    const result = await setSlackAuthorizedChannels(
      integrationId,
      channels.map((channel) => channel.id),
    );
    if ("error" in result) {
      throw new Error(`channelsRecordedElsewhere: ${result.error}`);
    }
  }

  /** Whether the picked channels can be saved — false when there is nothing new to save. */
  offersChannelsSave(): boolean {
    const button = this.buttonByText(/Save channels/);
    return button !== null && !button.disabled;
  }

  /**
   * Try to save channels the API refuses and hand back what the user is told.
   * A save that succeeds fails the test rather than timing out.
   */
  async refusedChannelsSave(names: string[]): Promise<string> {
    await this.pickChannels(names);
    await this.saveChannels();

    return this.waitFor(
      () => {
        const authorized = this.authorizedChannelNames() ?? [];
        if (names.every((name) => authorized.includes(name))) {
          throw new Error(
            `refusedChannelsSave: ${names.join(", ")} were recorded, not refused`,
          );
        }
        return this.toastText(/Could not save the destination channels/);
      },
      15000,
      "the refused channels save",
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

  /** The names the "Prowler posts to …" summary carries, or null while unsettled. */
  private authorizedChannelNames(): string[] | null {
    // The keyed element, not a text search: the card's subtitle also starts
    // with "Prowler posts to".
    const summary = this.q("[data-authorized-channels]");
    const text = (summary?.textContent ?? "").trim();
    if (!/^Prowler posts to /.test(text)) return null;

    return Array.from(text.matchAll(/#([^\s,.]+)/g), (match) => match[1]);
  }

  /** The channels recorded as the integration's authorized destinations. */
  async authorizedChannels(): Promise<string[]> {
    const settled = await this.waitFor<
      string[] | typeof NO_AUTHORIZED_CHANNELS
    >(
      () =>
        this.authorizedChannelNames() ??
        (this.containsText(/No destination channels authorized yet/)
          ? NO_AUTHORIZED_CHANNELS
          : null),
      10000,
      "the authorized destination channels",
    );
    return settled === NO_AUTHORIZED_CHANNELS ? [] : settled;
  }

  /**
   * What the closed picker shows: a chip per selected channel, each carrying
   * whether the chip itself marks the channel private.
   */
  async authorizedChannelChips(): Promise<ChannelChip[]> {
    const chips = await this.waitFor(
      () => {
        const found = Array.from(
          this.container.querySelectorAll<HTMLElement>(
            '[data-slot="multiselect-value"] [data-selected-item]',
          ),
        );
        return found.length > 0 ? found : null;
      },
      10000,
      "the authorized channel chips",
    );

    return chips.map((chip) => {
      const text = (chip.textContent ?? "").trim();
      return {
        name: text.replace(/^Private/, "").replace(/^#/, ""),
        isPrivate: /^Private/.test(text),
      };
    });
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
