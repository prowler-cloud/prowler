/**
 * Page-level test harness for the Alerts page (Vitest Browser Mode).
 *
 * A client renderer cannot render an async server component, so the page is
 * called and the element it returns is what gets rendered.
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
  /** No Slack workspace both enabled and connected. */
  NO_INTEGRATION: "no-integration",
  /** Workspace connected, no channel eligible yet. */
  EMPTY_POOL: "empty-pool",
  POPULATED: "populated",
} as const;

export type ChannelFieldState =
  (typeof CHANNEL_FIELD_STATE)[keyof typeof CHANNEL_FIELD_STATE];

export interface SelectedChannelChip {
  name: string;
  isPrivate: boolean;
}

interface RuleWriteChannel {
  id: string;
}

interface RuleWriteAttributes {
  schema_version?: number;
  slack_channels?: RuleWriteChannel[];
}

interface RuleWriteData {
  type?: string;
  attributes?: RuleWriteAttributes;
}

interface RuleWriteEnvelope {
  data?: RuleWriteData;
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

  async mount(
    searchParams: Record<string, string | undefined> = {},
  ): Promise<void> {
    window.history.replaceState(null, "", "/alerts");
    this.wireHandlers();

    render(await AlertsPage({ searchParams: Promise.resolve(searchParams) }));
    await this.waitForText(/Get notified when findings match/);
  }

  /** Rules are created from Findings (seed flow), never from the alerts page. */
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

  async openCreateModal(): Promise<void> {
    await this.clickButton(/Create Alert/);
    await this.waitFor(() => this.dialog(), 10000, "the create alert modal");
  }

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

  async saveRule(): Promise<void> {
    await this.submitModal();
    await this.waitFor(
      () => this.dialog() === null,
      10000,
      "the alert modal to close after saving",
    );
  }

  /**
   * Only newly added channels are validated (contract 6.3), so provoking a
   * channel refusal needs options that went stale mid-edit.
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
    // The error class is shared and first-in-DOM-order wins, so prefer the
    // form-level error: it is the only `div`, every field-scoped one is a `p`.
    const error =
      dialog.querySelector<HTMLElement>("div.text-text-error-primary") ??
      dialog.querySelector<HTMLElement>(".text-text-error-primary");
    const text = (error?.textContent ?? "").trim();
    return text.length > 0 ? text : null;
  }

  async savedRuleChannels(): Promise<string[] | undefined> {
    const body = await this.lastRuleWriteBody();
    return body?.data?.attributes?.slack_channels?.map((channel) => channel.id);
  }

  /**
   * Matched by payload, not by method or path: `/alerts/rules` prefixes the
   * seed and preview endpoints, and the enable/disable toggle reuses both the
   * write's URL and its type — only a real write carries `schema_version`.
   */
  private async lastRuleWriteBody(): Promise<RuleWriteEnvelope | null> {
    for (const entry of [...this.requestLog].reverse()) {
      const body = await AlertsPageHarness.parsedBody(entry.request);
      if (
        body?.data?.type === "alert-rules" &&
        body.data.attributes?.schema_version !== undefined
      ) {
        return body;
      }
    }
    return null;
  }

  private static async parsedBody(
    request: Request,
  ): Promise<RuleWriteEnvelope | null> {
    try {
      return (await request.clone().json()) as RuleWriteEnvelope;
    } catch {
      return null;
    }
  }

  // --- The channel destination field ---------------------------------------

  private channelField(): HTMLElement | null {
    return document.querySelector<HTMLElement>("[data-alert-channels-state]");
  }

  async channelFieldState(): Promise<ChannelFieldState> {
    const field = await this.waitFor(
      () => this.channelField(),
      10000,
      "the channel destination field",
    );
    return field.getAttribute("data-alert-channels-state") as ChannelFieldState;
  }

  async channelFieldNotice(): Promise<string> {
    const notice = await this.waitFor(
      () => document.querySelector<HTMLElement>("[data-alert-channels-notice]"),
      10000,
      "the channel destination notice",
    );
    return (notice.textContent ?? "").replace(/\s+/g, " ").trim();
  }

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
   * The options inside the popover THIS trigger controls, correlated through
   * `aria-controls`: two pickers share the page and the MultiSelect keeps a
   * hidden mirror of its items, so an unscoped `[role="option"]` query can
   * answer for the wrong one.
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

  async pickRecipients(emails: string[]): Promise<void> {
    for (const email of emails) {
      let picked = false;
      for (let attempt = 0; attempt < 3 && !picked; attempt += 1) {
        const options = await this.openPicker("#alert-recipients");
        // The picker stays open between attempts: re-clicking an item the last
        // attempt did select would toggle it back off.
        if (this.isRecipientSelected(email)) {
          picked = true;
          break;
        }
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
            () => this.isRecipientSelected(email),
            2000,
            `the ${email} chip`,
          )) ?? false;
      }
      if (!picked) {
        throw new Error(`pickRecipients: ${email} never showed as selected`);
      }
    }
    await this.closePicker("#alert-recipients");
  }

  /**
   * Closed by clicking the dialog title. Not Escape — with focus outside the
   * popover it reaches the dialog and closes the whole modal. Not the trigger
   * — its chips remove on click, silently dropping a selection.
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

  async offeredChannels(): Promise<string[]> {
    const options = await this.openChannelPicker();
    const names = options.map(AlertsPageHarness.optionChannelName);
    await this.closeChannelPicker();
    return names;
  }

  async isChannelOfferedAsPrivate(name: string): Promise<boolean> {
    const options = await this.openChannelPicker();
    const option = options.find(
      (candidate) => AlertsPageHarness.optionChannelName(candidate) === name,
    );
    await this.closeChannelPicker();
    return /Private/.test(option?.textContent ?? "");
  }

  /**
   * Always scoped to one field and matched exactly, never document-wide: two
   * pickers share the open form, and a private chip reads
   * `Private#security-alerts`, which contains `#security` — the other fixture
   * channel.
   */
  private static chipTexts(scope: ParentNode): string[] {
    return Array.from(
      scope.querySelectorAll<HTMLElement>("[data-selected-item]"),
    ).map((chip) => (chip.textContent ?? "").replace(/\s+/g, " ").trim());
  }

  /** The chip renders `#name` with an sr-only "Private" marker. */
  private static toChannelChip(text: string): SelectedChannelChip {
    return {
      isPrivate: /Private/.test(text),
      name: text
        .replace(/Private/g, "")
        .trim()
        .replace(/^#/, ""),
    };
  }

  private isChannelSelected(name: string): boolean {
    const field = this.channelField();
    if (!field) return false;
    return AlertsPageHarness.chipTexts(field)
      .map(AlertsPageHarness.toChannelChip)
      .some((chip) => chip.name === name);
  }

  private isRecipientSelected(email: string): boolean {
    const trigger = this.q("#alert-recipients");
    return (
      trigger !== null && AlertsPageHarness.chipTexts(trigger).includes(email)
    );
  }

  /**
   * Each pick is verified against the chip the user sees, then re-resolved and
   * re-clicked: the click can land on a node the selection re-render already
   * replaced, and a native click on a detached node never reaches React.
   */
  async pickChannels(names: string[]): Promise<void> {
    for (const name of names) {
      let picked = false;
      for (let attempt = 0; attempt < 3 && !picked; attempt += 1) {
        const options = await this.openChannelPicker();
        // The picker stays open between attempts: re-clicking an item the last
        // attempt did select would toggle it back off.
        if (this.isChannelSelected(name)) {
          picked = true;
          break;
        }
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
            () => this.isChannelSelected(name),
            2000,
            `the #${name} chip`,
          )) ?? false;
      }
      if (!picked) {
        throw new Error(`pickChannels: #${name} never showed as selected`);
      }
    }
    await this.closeChannelPicker();
  }

  async selectedChannelChips(): Promise<SelectedChannelChip[]> {
    const field = await this.waitFor(
      () => this.channelField(),
      10000,
      "the channel destination field",
    );
    return AlertsPageHarness.chipTexts(field).map(
      AlertsPageHarness.toChannelChip,
    );
  }

  // --- The alerts list ------------------------------------------------------

  /**
   * No caller on this branch: the Destinations column lands in S3
   * (`feature/alerts-destinations-column`), which consumes this. Not dead code.
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
