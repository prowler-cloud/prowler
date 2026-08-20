/**
 * Page-level test harness for the Alerts page (Vitest Browser Mode).
 *
 * A client renderer cannot render an async server component, so the page is
 * called and the element it returns is what gets rendered — the providers and
 * Slack harnesses' pattern.
 *
 * The channel-destination readers are the harness side of the S2 contract:
 * the alert form's channels field renders a wrapper carrying
 * `data-alert-channels-state` (`no-integration` | `empty-pool` | `populated`),
 * its explanatory copy under `data-alert-channels-notice`, and the shared
 * multi-select's trigger as `#slack-channels`.
 */

import { createElement } from "react";

import { BrowserHarness } from "@/__tests__/browser-harness";
import { handlersForAlerts } from "@/__tests__/msw/handlers/alerts";
import type { AlertsFixture } from "@/__tests__/msw/handlers/alerts.fixtures";
import { worker } from "@/__tests__/msw/worker";
import { render } from "@/__tests__/render-browser";
import type { AlertsFilterBag } from "@/app/(prowler)/alerts/_types";

import { SeedFromFindingsButton } from "./_components/seed-from-findings-button";
import AlertsPage from "./page";

export const CHANNEL_FIELD_STATE = {
  /** No enabled and connected Slack workspace: visible, disabled, explains itself. */
  NO_INTEGRATION: "no-integration",
  /** Workspace connected, no channel eligible yet. */
  EMPTY_POOL: "empty-pool",
  /** The eligible channels are on offer. */
  POPULATED: "populated",
} as const;

export type ChannelFieldState =
  (typeof CHANNEL_FIELD_STATE)[keyof typeof CHANNEL_FIELD_STATE];

/** A selected channel as the user reads it off the closed field. */
export interface SelectedChannelChip {
  name: string;
  isPrivate: boolean;
}

const DEFAULT_CREATE_FILTER_BAG: AlertsFilterBag = {
  "filter[severity__in]": ["critical"],
};

export class AlertsPageHarness extends BrowserHarness<AlertsFixture> {
  private wireHandlers(): void {
    worker.use(...handlersForAlerts(this.fixture));
    this.trackRequests(worker);
  }

  // --- Mounting -----------------------------------------------------------

  /** Open the alerts page, the way a visit does. */
  async mount(
    searchParams: Record<string, string | undefined> = {},
  ): Promise<void> {
    window.history.replaceState(null, "", "/alerts");
    this.wireHandlers();

    render(await AlertsPage({ searchParams: Promise.resolve(searchParams) }));
    await this.waitForText(/Get notified when findings match/);
  }

  /**
   * Mount the creation entry as the findings page composes it — the alerts
   * page itself only edits; rules are created from Findings (seed flow).
   */
  mountCreateEntry(
    filterBag: AlertsFilterBag = DEFAULT_CREATE_FILTER_BAG,
  ): void {
    window.history.replaceState(null, "", "/findings");
    this.wireHandlers();

    render(createElement(SeedFromFindingsButton, { filterBag }));
  }

  // --- The alert modal ------------------------------------------------------

  private dialog(): HTMLElement | null {
    return document.querySelector<HTMLElement>('[role="dialog"]');
  }

  /** Seed from the mounted create entry and wait for the modal. */
  async openCreateModal(): Promise<void> {
    await this.clickButton(/Create Alert/);
    await this.waitFor(() => this.dialog(), 10000, "the create alert modal");
  }

  /** Open a listed rule for editing, by its name. */
  async openEditModal(ruleName: string): Promise<void> {
    const nameButton = await this.waitFor(
      () =>
        Array.from(
          this.container.querySelectorAll<HTMLButtonElement>("button"),
        ).find((button) => (button.textContent ?? "").trim() === ruleName),
      10000,
      `the listed rule "${ruleName}"`,
    );
    await this.clickElement(nameButton, { fallbackToDomClick: true });
    await this.waitFor(() => this.dialog(), 10000, "the edit alert modal");
  }

  /** Submit the open modal (Create or Save) and wait for it to close. */
  async saveRule(): Promise<void> {
    await this.submitModal();
    await this.waitFor(
      () => this.dialog() === null,
      10000,
      "the alert modal to close after saving",
    );
  }

  /**
   * Submit the open modal expecting a refusal, and hand back what the user is
   * told. A save that closes the modal fails the test rather than timing out.
   */
  async refusedRuleSave(): Promise<string> {
    await this.submitModal();
    return this.waitFor(
      () => {
        if (this.dialog() === null) {
          throw new Error("refusedRuleSave: the save landed, not refused");
        }
        return this.modalErrorText();
      },
      10000,
      "the refused rule save",
    );
  }

  private async submitModal(): Promise<void> {
    const dialog = this.dialog();
    if (!dialog) throw new Error("submitModal: no alert modal is open");
    const submit = await this.waitFor(
      () => this.buttonByText(/^(Create|Save)$/, dialog),
      5000,
      "the modal submit button",
    );
    await this.clickElement(submit, { fallbackToDomClick: true });
  }

  private modalErrorText(): string | null {
    const dialog = this.dialog();
    if (!dialog) return null;
    const error = dialog.querySelector<HTMLElement>(".text-text-error-primary");
    const text = (error?.textContent ?? "").trim();
    return text.length > 0 ? text : null;
  }

  /**
   * The channel ids the last rule write actually submitted, read off the
   * contract's `[{id}, …]` write shape.
   */
  async savedRuleChannels(): Promise<string[] | undefined> {
    const method =
      this.countRequests("POST", "/alerts/rules") >
      this.countRequests("PATCH", "/alerts/rules")
        ? "POST"
        : "PATCH";
    const body = await this.lastRequestBody<{
      data?: { attributes?: { slack_channels?: { id: string }[] } };
    }>(method, "/alerts/rules");
    return body?.data?.attributes?.slack_channels?.map((channel) => channel.id);
  }

  // --- The channel destination field ---------------------------------------

  private channelField(): HTMLElement | null {
    return document.querySelector<HTMLElement>("[data-alert-channels-state]");
  }

  /** Which of its three states the channel destination is presenting. */
  async channelFieldState(): Promise<ChannelFieldState> {
    const field = await this.waitFor(
      () => this.channelField(),
      10000,
      "the channel destination field",
    );
    return field.getAttribute("data-alert-channels-state") as ChannelFieldState;
  }

  /** The copy explaining a degraded state, wherever the field renders it. */
  async channelFieldNotice(): Promise<string> {
    const notice = await this.waitFor(
      () => document.querySelector<HTMLElement>("[data-alert-channels-notice]"),
      10000,
      "the channel destination notice",
    );
    return (notice.textContent ?? "").replace(/\s+/g, " ").trim();
  }

  /** The affordance a degraded state offers toward the integration page. */
  integrationAffordanceHref(): string | null {
    const scopes: (ParentNode | null)[] = [
      document.querySelector("[data-alert-channels-notice]"),
      this.channelField(),
    ];
    for (const scope of scopes) {
      const link = scope?.querySelector<HTMLAnchorElement>(
        'a[href="/integrations/slack"]',
      );
      if (link) return link.getAttribute("href");
    }
    return null;
  }

  /**
   * The options inside the popover THIS trigger controls, or null. Correlated
   * through `aria-controls`: two pickers share the page (channels,
   * recipients) and the MultiSelect also keeps a hidden mirror of its items,
   * so any unscoped `[role="option"]` query can answer for the wrong picker.
   */
  private static optionsControlledBy(
    trigger: HTMLElement,
  ): HTMLElement[] | null {
    const contentId = trigger.getAttribute("aria-controls");
    const content = contentId ? document.getElementById(contentId) : null;
    if (!content || content.getAttribute("data-state") !== "open") return null;
    const options = Array.from(
      content.querySelectorAll<HTMLElement>('[role="option"]'),
    );
    return options.length > 0 ? options : null;
  }

  private async openPicker(triggerSelector: string): Promise<HTMLElement[]> {
    const trigger = await this.waitFor<HTMLElement>(
      () => this.q(triggerSelector),
      10000,
      `the ${triggerSelector} picker`,
    );
    const mounted = () => AlertsPageHarness.optionsControlledBy(trigger);

    const alreadyOpen = mounted();
    if (alreadyOpen) return alreadyOpen;

    await this.clickElement(trigger, { fallbackToDomClick: true });

    let options = await this.waitForOrNull(mounted, 2000, "the picker options");
    if (!options) {
      await this.user.keyboard("{Enter}");
      options = await this.waitForOrNull(mounted, 8000, "the picker options");
    }
    if (!options) {
      throw new Error(`openPicker: ${triggerSelector} offered nothing`);
    }
    return options;
  }

  private async openChannelPicker(): Promise<HTMLElement[]> {
    return this.openPicker("#slack-channels");
  }

  /** Whether the channel picker is rendered but refuses interaction. */
  async channelPickerDisabled(): Promise<boolean> {
    const trigger = await this.waitFor(
      () => this.q("#slack-channels"),
      10000,
      "the channel picker trigger",
    );
    return (
      (trigger as HTMLButtonElement).disabled ||
      trigger.getAttribute("aria-disabled") === "true" ||
      trigger.hasAttribute("disabled")
    );
  }

  /**
   * Toggle the named recipient emails in the recipients picker, verifying
   * each pick against its chip like `pickChannels` does.
   */
  async pickRecipients(emails: string[]): Promise<void> {
    for (const email of emails) {
      let picked = false;
      for (let attempt = 0; attempt < 3 && !picked; attempt += 1) {
        const options = await this.openPicker("#alert-recipients");
        const option = options.find((candidate) =>
          (candidate.textContent ?? "").includes(email),
        );
        if (!option) {
          await this.closePicker("#alert-recipients");
          throw new Error(`pickRecipients: no recipient "${email}" is offered`);
        }
        await this.clickElement(option, { fallbackToDomClick: true });
        picked =
          (await this.waitForOrNull(
            () => this.chipContaining(email),
            2000,
            `the ${email} chip`,
          )) !== null;
      }
      if (!picked) {
        throw new Error(`pickRecipients: ${email} never showed as selected`);
      }
    }
    await this.closePicker("#alert-recipients");
  }

  /**
   * Close an open picker by clicking a neutral spot inside the dialog (its
   * title). Not a bare Escape — with focus outside the popover it reaches the
   * dialog and closes the whole modal. Not the trigger either — its chips
   * remove-on-click, so a click landing on one silently drops a selection.
   */
  private async closePicker(triggerSelector: string): Promise<void> {
    const trigger = this.q(triggerSelector);
    const isOpen = () => {
      const contentId = trigger?.getAttribute("aria-controls");
      const content = contentId ? document.getElementById(contentId) : null;
      return content?.getAttribute("data-state") === "open";
    };
    if (trigger && isOpen()) {
      const neutral =
        this.dialog()?.querySelector<HTMLElement>("h2") ?? trigger;
      await this.clickElement(neutral, { fallbackToDomClick: true });
      await this.waitForOrNull(() => !isOpen(), 2000, "the picker to close");
    }
    await this.waitForTransition();
  }

  private async closeChannelPicker(): Promise<void> {
    await this.closePicker("#slack-channels");
  }

  private static optionChannelName(option: HTMLElement): string {
    return (
      option.getAttribute("data-channel") ??
      (option.textContent ?? "")
        .replace(/Private/g, "")
        .trim()
        .replace(/^#/, "")
    );
  }

  /** The channels offered for the rule, in the order the picker lists them. */
  async offeredChannels(): Promise<string[]> {
    const options = await this.openChannelPicker();
    const names = options.map(AlertsPageHarness.optionChannelName);
    await this.closeChannelPicker();
    return names;
  }

  /** Whether the channel offered under `name` is presented as private. */
  async isChannelOfferedAsPrivate(name: string): Promise<boolean> {
    const options = await this.openChannelPicker();
    const option = options.find(
      (candidate) => AlertsPageHarness.optionChannelName(candidate) === name,
    );
    await this.closeChannelPicker();
    return /Private/.test(option?.textContent ?? "");
  }

  /** A visible chip whose text contains `text`, anywhere in the open form. */
  private chipContaining(text: string): HTMLElement | null {
    return (
      Array.from(
        document.querySelectorAll<HTMLElement>("[data-selected-item]"),
      ).find((chip) => (chip.textContent ?? "").includes(text)) ?? null
    );
  }

  /**
   * Toggle the named channels in the picker, then close it. Each pick is
   * verified against the chip the user sees and retried when the click
   * landed on a node the selection re-render had already replaced.
   */
  async pickChannels(names: string[]): Promise<void> {
    for (const name of names) {
      let picked = false;
      for (let attempt = 0; attempt < 3 && !picked; attempt += 1) {
        const options = await this.openChannelPicker();
        const option = options.find(
          (candidate) =>
            AlertsPageHarness.optionChannelName(candidate) === name,
        );
        if (!option) {
          await this.closeChannelPicker();
          throw new Error(
            `pickChannels: no channel named "${name}" is offered`,
          );
        }
        await this.clickElement(option, { fallbackToDomClick: true });
        picked =
          (await this.waitForOrNull(
            () => this.chipContaining(`#${name}`),
            2000,
            `the #${name} chip`,
          )) !== null;
      }
      if (!picked) {
        throw new Error(`pickChannels: #${name} never showed as selected`);
      }
    }
    await this.closeChannelPicker();
  }

  /**
   * The rule's selected channels as the closed field shows them — name and
   * privacy read from the chip the user sees.
   */
  async selectedChannelChips(): Promise<SelectedChannelChip[]> {
    const field = await this.waitFor(
      () => this.channelField(),
      10000,
      "the channel destination field",
    );
    const chips = Array.from(
      field.querySelectorAll<HTMLElement>("[data-selected-item]"),
    );
    return chips.map((chip) => {
      const text = (chip.textContent ?? "").replace(/\s+/g, " ").trim();
      return {
        isPrivate: /Private/.test(text),
        // The chip renders `#name` with an sr-only "Private" marker.
        name: text
          .replace(/Private/g, "")
          .trim()
          .replace(/^#/, ""),
      };
    });
  }

  // --- The alerts list ------------------------------------------------------

  /** The names of the listed rules, in table order. */
  async listedRules(): Promise<string[]> {
    const rows = await this.waitFor(
      () => {
        const found = Array.from(
          this.container.querySelectorAll<HTMLTableRowElement>("tbody tr"),
        );
        return found.length > 0 ? found : null;
      },
      10000,
      "the alerts list",
    );
    return rows.map((row) =>
      (row.querySelector("button")?.textContent ?? "").trim(),
    );
  }

  /**
   * The destinations summary the list shows for a rule, without opening it —
   * the Destinations column once S3 lands (Recipients until then).
   */
  async ruleDestinationsSummary(ruleName: string): Promise<string> {
    const headers = Array.from(
      this.container.querySelectorAll<HTMLElement>("thead th"),
    );
    const columnIndex = headers.findIndex((header) =>
      /Destinations|Recipients/.test(header.textContent ?? ""),
    );
    if (columnIndex === -1) {
      throw new Error("ruleDestinationsSummary: no destinations column");
    }

    const row = await this.waitFor(
      () =>
        Array.from(
          this.container.querySelectorAll<HTMLTableRowElement>("tbody tr"),
        ).find((candidate) => (candidate.textContent ?? "").includes(ruleName)),
      10000,
      `the listed rule "${ruleName}"`,
    );
    const cell = row.querySelectorAll("td")[columnIndex];
    return (cell?.textContent ?? "").replace(/\s+/g, " ").trim();
  }
}
