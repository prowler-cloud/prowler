/**
 * Page-level test harness for the providers page + organizations onboarding
 * wizard (Vitest Browser Mode).
 *
 * Mirrors the attack-paths harness pattern: it owns mounting and MSW wiring and
 * exposes semantic methods so tests interact through intent ("choose AWS
 * Organizations", "authenticate", "test connections") rather than raw
 * selectors. Request assertions are domain-named too (`applyCallCount`,
 * `waitForOrganizationRename`, `taskPollCount`, …); the raw HTTP-verb+path
 * `waitForRequest` primitive stays internal. Discovery/connection polling is
 * real (MSW returns terminal states on the first poll), so flow methods wait
 * on the resulting UI.
 */

import { BrowserHarness } from "@/__tests__/browser-harness";
import {
  handlersForOrganizations,
  HIERARCHY_READ_FAILURE,
  type HierarchyReadFailure,
} from "@/__tests__/msw/handlers/organizations";
import type { OrgFixture } from "@/__tests__/msw/handlers/organizations.fixtures";
import { worker } from "@/__tests__/msw/worker";
import { render } from "@/__tests__/render-browser";
import {
  ADD_PROVIDER_SEARCH_PARAM,
  ADD_PROVIDER_SEARCH_VALUE,
} from "@/lib/providers-navigation";
import type { SearchParamsProps } from "@/types";

import { ProvidersTabContent } from "./providers-tab-content";

const INITIAL_SCAN_LABEL = "Launch an initial scan now for immediate findings";

interface MountOptions {
  /** Seed `?addProvider=true` so the wizard opens on mount. Default true. */
  openWizard?: boolean;
  /** Which hierarchy read fails, so the loader derives the status. Default none. */
  hierarchyFailure?: HierarchyReadFailure;
}

/**
 * Attributes a `POST /organizations` carries. `root_external_id` is deliberately
 * absent: the API derives every type's root, so a test asserting the client does
 * not send one reads it off the parsed body, not off this shape.
 */
export interface OrganizationCreateAttributes {
  name?: string;
  org_type?: string;
  external_id?: string;
}

export class ProvidersPageHarness extends BrowserHarness<OrgFixture> {
  get applyCallCount(): number {
    return this.countRequests("POST", "/apply");
  }

  /**
   * Whether any apply asked the endpoint to include related resources, which it
   * rejects outright — a tripwire, not a preference.
   */
  applySentIncludeParam(): boolean {
    return this.requestLog.some(
      (entry) =>
        entry.method === "POST" &&
        entry.url.includes("/apply") &&
        entry.url.includes("include="),
    );
  }

  /** Single-provider reads — one per created provider is the N+1 this avoids. */
  get singleProviderFetchCount(): number {
    return this.requestLog.filter(
      (entry) =>
        entry.method === "GET" && /\/providers\/[^/?]+$/.test(entry.url),
    ).length;
  }

  /** Filtered provider-list reads, which resolve every created uid at once. */
  get providerUidLookupCount(): number {
    return this.requestLog.filter(
      (entry) =>
        entry.method === "GET" && entry.url.includes("filter%5Bid__in%5D"),
    ).length;
  }

  private get connectionCallCount(): number {
    return this.countRequests("POST", "/connection");
  }

  /** How many times the page fetched the organization list over HTTP. */
  get organizationFetchCount(): number {
    return this.countRequests("GET", "/organizations");
  }

  /**
   * Attributes the organization was created with. Matched on the collection path
   * itself rather than a substring: the nested `discover` and `apply` POSTs also
   * live under `/organizations` and carry no body to read.
   */
  async createdOrganizationAttributes(): Promise<OrganizationCreateAttributes | null> {
    const entry = [...this.requestLog]
      .reverse()
      .find(
        (r) =>
          r.method === "POST" &&
          new URL(r.url).pathname.endsWith("/organizations"),
      );
    if (!entry) return null;

    const body = (await entry.request.clone().json()) as {
      data?: { attributes?: OrganizationCreateAttributes };
    };
    return body?.data?.attributes ?? null;
  }

  /**
   * How many times the page fetched the organization hierarchy over HTTP —
   * either route, so this stays a tripwire for "the hierarchy is still
   * requested" across the deprecated → canonical migration.
   */
  get hierarchyFetchCount(): number {
    return (
      this.countRequests("GET", "/organizational-units") +
      this.countRequests("GET", "/organization-nodes")
    );
  }

  /** How many bulk schedule saves the launch step issued. */
  get scheduleBulkCallCount(): number {
    return this.countRequests("POST", "/schedules/bulk");
  }

  /** How many organization bulk scan operations were launched. */
  get organizationBulkScanCallCount(): number {
    return this.countRequests("POST", "/scans/bulk");
  }

  // --- Mount + environment ------------------------------------------------

  private seedWizardUrl(openWizard: boolean): void {
    const params = new URLSearchParams();
    if (openWizard) {
      params.set(ADD_PROVIDER_SEARCH_PARAM, ADD_PROVIDER_SEARCH_VALUE);
    }
    const query = params.toString();
    window.history.replaceState(
      null,
      "",
      query ? `/providers?${query}` : "/providers",
    );
  }

  private searchParams(): SearchParamsProps {
    return Object.fromEntries(new URLSearchParams(window.location.search));
  }

  /**
   * Mount production's own providers-tab content, the component
   * `providers/page.tsx` renders inside its Suspense boundary. It owns the whole
   * data path — deriving `isCloud()`, loading the view data (providers, groups,
   * schedules, organization hierarchy) and the scan configurations, then wiring
   * them into the view — so nothing here duplicates it and drift can't hide in
   * the harness. Requests go through MSW; the shared `render` supplies the app
   * shell (session, theme, Toaster) the production layout provides.
   *
   * It's an async server component: React's client renderer can't render async
   * components, so it is called and its returned element is what gets rendered.
   * (`page.tsx`'s default export can't be used at all — it returns Suspense
   * wrapping async children, which only a server renderer resolves.)
   */
  async mount({
    openWizard = true,
    hierarchyFailure = HIERARCHY_READ_FAILURE.NONE,
  }: MountOptions = {}): Promise<void> {
    this.seedWizardUrl(openWizard);
    worker.use(...handlersForOrganizations(this.fixture, { hierarchyFailure }));
    this.trackRequests(worker);

    render(await ProvidersTabContent({ searchParams: this.searchParams() }));
  }

  // --- Wizard: connect step ----------------------------------------------

  /** Select a provider in the wizard's provider picker (auto-advances to step 2). */
  async selectProviderType(
    name: RegExp = /Amazon Web Services/,
  ): Promise<void> {
    const option = await this.waitFor(() => this.byRoleName("option", name));
    await this.user.click(option);
  }

  /** Click a method card in a provider's method selector by its title. */
  async chooseMethod(name: RegExp): Promise<void> {
    const card = await this.waitFor(() => this.byRoleName("radio", name));
    await this.user.click(card);
  }

  /** Enter the AWS Organizations onboarding flow from a fresh wizard. */
  async chooseAwsOrganizations(): Promise<void> {
    await this.selectProviderType(/Amazon Web Services/);
    await this.chooseMethod(/Add Multiple Accounts With AWS Organizations/);
    await this.waitForText(/Organization Details/);
  }

  /** Select GCP and open the GCP Organization method card (no advance wait). */
  async chooseGcpOrganizationsMethod(): Promise<void> {
    await this.selectProviderType(/Google Cloud Platform/);
    await this.chooseMethod(/Add Multiple Projects With GCP Organization/);
  }

  /** Enter the GCP Organization onboarding flow from a fresh wizard. */
  async chooseGcpOrganizations(): Promise<void> {
    await this.chooseGcpOrganizationsMethod();
    await this.waitForText(/Organization Details/);
  }

  /** Select Azure and open the Management Group method card (no advance wait). */
  async chooseAzureOrganizationsMethod(): Promise<void> {
    await this.selectProviderType(/Microsoft Azure/);
    await this.chooseMethod(
      /Add Multiple Subscriptions With Azure Management Group/,
    );
  }

  /** Enter the Azure Management Group onboarding flow from a fresh wizard. */
  async chooseAzureOrganizations(): Promise<void> {
    await this.chooseAzureOrganizationsMethod();
    await this.waitForText(/Organization Details/);
  }

  /** Wait until the wizard shows the selected provider's method fork. */
  async waitForMethodStep(): Promise<void> {
    await this.waitForText(/Select a method to add your/);
  }

  /** Whether the organization setup step is showing (the flow actually started). */
  hasOrganizationSetupStep(): boolean {
    return this.containsText(/Organization Details/);
  }

  /** Whether the step links out to the given documentation URL fragment. */
  hasDocsLinkTo(urlFragment: string): boolean {
    return this.q(`a[href*="${urlFragment}"]`) !== null;
  }

  // --- Wizard: GCP setup step --------------------------------------------

  async fillGcpOrgDetails(orgId: string, name?: string): Promise<void> {
    const orgIdInput = await this.waitFor(() => this.inputByName("gcpOrgId"));
    await this.user.fill(orgIdInput, orgId);
    if (name !== undefined) {
      const nameInput = this.inputByName("organizationName");
      if (nameInput) await this.user.fill(nameInput, name);
    }
  }

  /** Paste a service-account key JSON into the GCP authentication step. */
  async fillGcpServiceAccountKey(json: string): Promise<void> {
    const textarea = await this.waitFor(
      () =>
        this.q(
          'textarea[name="serviceAccountKey"]',
        ) as HTMLTextAreaElement | null,
    );
    await this.user.fill(textarea, json);
  }

  // --- Wizard: Azure setup step ------------------------------------------

  /**
   * Fill the Azure organization-details phase. The tenant is the only identifier
   * collected: onboarding is always scoped to the tenant root Management Group,
   * which the API derives from it.
   */
  async fillAzureOrgDetails(tenantId: string, name?: string): Promise<void> {
    const tenantInput = await this.waitFor(() => this.inputByName("tenantId"));
    await this.user.fill(tenantInput, tenantId);
    if (name !== undefined) {
      const nameInput = this.inputByName("organizationName");
      if (nameInput) await this.user.fill(nameInput, name);
    }
  }

  /** Fill the Azure service-principal credentials on the authentication step. */
  async fillAzureCredentials(
    clientId: string,
    clientSecret: string,
  ): Promise<void> {
    const clientIdInput = await this.waitFor(() =>
      this.inputByName("clientId"),
    );
    await this.user.fill(clientIdInput, clientId);
    const secretInput = await this.waitFor(() =>
      this.inputByName("clientSecret"),
    );
    await this.user.fill(secretInput, clientSecret);
  }

  // --- Wizard: AWS setup step --------------------------------------------

  async fillAwsOrgDetails(orgId: string, name?: string): Promise<void> {
    const orgIdInput = await this.waitFor(() => this.inputByName("awsOrgId"));
    await this.user.fill(orgIdInput, orgId);
    if (name !== undefined) {
      const nameInput = this.inputByName("organizationName");
      if (nameInput) await this.user.fill(nameInput, name);
    }
  }

  /** Advance from the organization-details step to the authentication step. */
  async submitOrganizationDetails(): Promise<void> {
    await this.clickPrimary(/Next/);
  }

  /** Click the setup step's primary footer button ("Next" / "Authenticate"). */
  private async clickPrimary(name: RegExp): Promise<void> {
    const btn = await this.waitForButton(name);
    await this.user.click(btn);
  }

  async fillAwsAccess({
    ouId,
    roleArn,
  }: {
    ouId: string;
    roleArn: string;
  }): Promise<void> {
    const ouInput = await this.waitFor(() =>
      this.inputByName("organizationalUnitId"),
    );
    await this.user.fill(ouInput, ouId);
    const roleInput = await this.waitFor(() => this.inputByName("roleArn"));
    await this.user.fill(roleInput, roleArn);
    // Confirm the StackSet-deployed checkbox.
    const checkbox = await this.waitFor(() =>
      this.q('#stackSetDeployed, [name="stackSetDeployed"]'),
    );
    await this.user.click(checkbox);
  }

  /** Submit the authentication step, kicking off account discovery. */
  async authenticate(): Promise<void> {
    await this.clickPrimary(/Authenticate/);
  }

  // --- Wizard: credential replacement + discovery recovery -----------------

  /** Wait until the confirm-before-replace credential warning is showing. */
  async waitForCredentialReplaceWarning(): Promise<void> {
    await this.waitForText(/Replace existing credentials\?/);
  }

  /** Whether the warning states how many providers a replacement re-authenticates. */
  hasCredentialReplaceProviderCount(providerCount: number): boolean {
    return this.containsText(
      new RegExp(`re-authenticates its ${providerCount} providers?`),
    );
  }

  /** Confirm the credential replacement and continue the setup chain. */
  async confirmCredentialReplace(): Promise<void> {
    await this.clickButton(/Replace credentials/);
  }

  /** Wait until the app replaced (PATCHed) the organization secret. */
  async waitForSecretReplace(): Promise<void> {
    await this.waitForRequest("PATCH", "/organization-secrets/");
  }

  /**
   * Whether the pre-apply warning states how many already-onboarded candidates the
   * apply would overwrite, and names them. Noun-bound per organization type: the
   * warning saying the wrong noun is the failure this pins.
   */
  private hasOverwriteWarningFor(
    count: number,
    names: string[],
    noun: string,
  ): boolean {
    const states = this.containsText(
      new RegExp(
        `overwrite the credentials of ${count} already-onboarded ${noun}`,
      ),
    );
    return states && names.every((name) => this.containsText(new RegExp(name)));
  }

  hasApplyOverwriteWarning(
    projectCount: number,
    names: string[] = [],
  ): boolean {
    return this.hasOverwriteWarningFor(projectCount, names, "project");
  }

  /** The GCP counterpart above, in Azure's noun. */
  hasApplySubscriptionOverwriteWarning(
    subscriptionCount: number,
    names: string[] = [],
  ): boolean {
    return this.hasOverwriteWarningFor(
      subscriptionCount,
      names,
      "subscription",
    );
  }

  /** Confirm the pre-apply credential overwrite and continue into apply. */
  async confirmApplyOverwrite(): Promise<void> {
    await this.clickButton(/Replace and continue/);
  }

  /** Wait until a failed discovery surfaces its authentication error. */
  async waitForDiscoveryFailure(timeoutMs = 15000): Promise<void> {
    await this.waitForText(/Authentication failed/, timeoutMs);
  }

  /**
   * Wait until a failed discovery surfaces the actionable copy for its machine
   * code, rather than the type's generic authentication-failure fallback.
   */
  async waitForDiscoveryFailureReason(
    reason: RegExp,
    timeoutMs = 15000,
  ): Promise<void> {
    await this.waitForText(reason, timeoutMs);
  }

  /**
   * Whether that reason is showing — the negative half, for asserting which of
   * the competing failure strings the user was actually given.
   */
  hasDiscoveryFailureReason(reason: RegExp): boolean {
    return this.containsText(reason);
  }

  /** Retry a failed/timed-out discovery with a fresh one. */
  async retryDiscovery(): Promise<void> {
    await this.clickButton(/Retry discovery/);
  }

  /** Wait until the app has triggered at least `n` discoveries. */
  async waitForDiscoveryCount(n: number, timeoutMs = 15000): Promise<void> {
    await this.waitForRequest("POST", "/discover", n, timeoutMs);
  }

  // --- Wizard: selection step --------------------------------------------

  private get tree(): HTMLElement | null {
    return this.q('[role="tree"]');
  }

  private get treeItems(): HTMLElement[] {
    return Array.from(
      this.container.querySelectorAll<HTMLElement>('[role="treeitem"]'),
    );
  }

  private treeItemByText(text: RegExp): HTMLElement | null {
    return this.treeItems.find((el) => text.test(el.textContent ?? "")) ?? null;
  }

  // Noun-agnostic on purpose: the copy says "accounts" for AWS, "projects" for
  // GCP, "subscriptions" for Azure.
  private selectedCountText(): string {
    return (
      this.container.textContent?.match(
        /\d+ of \d+ (?:accounts|projects|subscriptions) selected/,
      )?.[0] ?? ""
    );
  }

  private hasSelectionSummary(
    selected: number,
    total: number,
    noun: string,
  ): boolean {
    return new RegExp(`${selected} of ${total} ${noun} selected`).test(
      this.selectedCountText(),
    );
  }

  async waitForSelectionTree(): Promise<HTMLElement> {
    return this.waitFor(() => this.tree);
  }

  /**
   * A container row identifies itself by its uid: a GCP folder ref, an AWS OU id,
   * or an Azure Management Group resource id. Anchored, because it is matched
   * against a single text node — see `textChunks`.
   */
  private static readonly CONTAINER_UID =
    /^(?:folders\/\d+|ou-[\w-]+|\/providers\/Microsoft\.Management\/managementGroups\/[\w.()-]+)$/;

  /**
   * A row's text, one entry per text node. The uid column and the name column
   * are adjacent, so `textContent` runs them together
   * ("…/managementGroups/archived" + "Archived") and a uid pattern reading the
   * whole row would swallow the display name.
   */
  private static textChunks(row: HTMLElement): string[] {
    const walker = document.createTreeWalker(row, NodeFilter.SHOW_TEXT);
    const chunks: string[] = [];
    for (let node = walker.nextNode(); node; node = walker.nextNode()) {
      const text = node.textContent?.trim();
      if (text) chunks.push(text);
    }
    return chunks;
  }

  private static containerUid(row: HTMLElement): string | null {
    return (
      ProvidersPageHarness.textChunks(row).find((chunk) =>
        ProvidersPageHarness.CONTAINER_UID.test(chunk),
      ) ?? null
    );
  }

  private get containerRows(): HTMLElement[] {
    return this.treeItems.filter(
      (item) => ProvidersPageHarness.containerUid(item) !== null,
    );
  }

  /**
   * Container rows carrying this label. Counted over rows, not through
   * `treeItemByText` (first match only), so a duplicated container is visible.
   */
  countContainerRows(label: string): number {
    return this.containerRows.filter((item) =>
      (item.textContent ?? "").includes(label),
    ).length;
  }

  /** Uids rendered by container rows — a row with an unresolved id has none. */
  containerRowUids(): string[] {
    return this.containerRows.flatMap(
      (item) => ProvidersPageHarness.containerUid(item) ?? [],
    );
  }

  /** Whether a candidate row is rendered inside the subtree of a container. */
  isCandidateNestedUnder(
    candidateUid: string,
    containerLabel: string,
  ): boolean {
    const container = this.treeItems.find(
      (item) =>
        (item.textContent ?? "").includes(containerLabel) &&
        item.parentElement?.querySelector('[role="group"]') !== null,
    );
    const group = container?.parentElement?.querySelector('[role="group"]');
    return (group?.textContent ?? "").includes(candidateUid);
  }

  /**
   * The note a container row shows when nothing under it can be selected, read
   * from the icon's accessible label so the assertion needs no hover.
   */
  inertContainerNote(containerLabel: string): string | null {
    const row = this.containerRows.find((item) =>
      (item.textContent ?? "").includes(containerLabel),
    );
    return (
      row?.querySelector('[role="img"]')?.getAttribute("aria-label") ?? null
    );
  }

  /** Whether a container row is inert (present, visibly non-selectable). */
  isContainerInert(containerLabel: string): boolean {
    const row = this.containerRows.find((item) =>
      (item.textContent ?? "").includes(containerLabel),
    );
    return row?.getAttribute("aria-disabled") === "true";
  }

  /** Whether a candidate currently has a row in the tree at all. */
  isCandidateVisible(uid: string): boolean {
    return this.treeItemByText(new RegExp(uid)) !== null;
  }

  /**
   * Click a container row itself (not its checkbox or chevron) to expand or
   * collapse it. Dispatched directly rather than through user-event, whose
   * actionability check rejects an `aria-disabled` row a real pointer can still
   * reach.
   */
  async clickContainerRow(containerLabel: string): Promise<void> {
    const row = await this.waitFor(
      () =>
        this.containerRows.find((item) =>
          (item.textContent ?? "").includes(containerLabel),
        ) ?? null,
    );
    row.click();
  }

  /**
   * Whether a candidate row's id spills out of its column or collides with the
   * alias input next to it. Measured from real layout boxes, not class names.
   */
  candidateRowOverflows(uid: string): boolean {
    const row = this.treeItemByText(new RegExp(uid));
    const idText = Array.from(
      row?.querySelectorAll<HTMLElement>("span") ?? [],
    ).find((span) => span.textContent === uid);
    const alias = row?.querySelector<HTMLInputElement>(
      "input:not([type='checkbox'])",
    );
    if (!idText || !alias) {
      throw new Error(`candidate ${uid} has no id text or no alias input`);
    }

    const idRect = idText.getBoundingClientRect();
    const columnRect = idText.parentElement!.getBoundingClientRect();
    // Sub-pixel layout rounding, not overflow.
    return (
      idRect.right > columnRect.right + 1 ||
      idRect.right > alias.getBoundingClientRect().left
    );
  }

  /** Current value of a candidate row's alias input. */
  candidateAliasValue(idText: RegExp): string | null {
    const item = this.treeItemByText(idText);
    const input = item?.querySelector<HTMLInputElement>(
      "input:not([type='checkbox'])",
    );
    return input?.value ?? null;
  }

  /** Wait until account discovery finishes and the selection summary renders. */
  async waitForAccountSelection(timeoutMs = 15000): Promise<void> {
    await this.waitForText(/of \d+ accounts selected/, timeoutMs);
  }

  /** Wait until the summary reads "<selected> of <total> accounts selected". */
  async waitForSelectedCount(
    selected: number,
    total: number,
    timeoutMs = 15000,
  ): Promise<void> {
    await this.waitForText(
      new RegExp(`${selected} of ${total} accounts selected`),
      timeoutMs,
    );
  }

  /** Whether the selection summary currently reads "<selected> of <total>". */
  hasSelectedCount(selected: number, total: number): boolean {
    return this.hasSelectionSummary(selected, total, "accounts");
  }

  /** Wait until project discovery finishes and the selection summary renders. */
  async waitForProjectSelection(timeoutMs = 15000): Promise<void> {
    await this.waitForText(/of \d+ projects selected/, timeoutMs);
  }

  /** Wait until the summary reads "<selected> of <total> projects selected". */
  async waitForSelectedProjectCount(
    selected: number,
    total: number,
    timeoutMs = 15000,
  ): Promise<void> {
    await this.waitForText(
      new RegExp(`${selected} of ${total} projects selected`),
      timeoutMs,
    );
  }

  /** Whether the summary reads "<selected> of <total> projects selected". */
  hasSelectedProjectCount(selected: number, total: number): boolean {
    return this.hasSelectionSummary(selected, total, "projects");
  }

  /** Wait until subscription discovery finishes and the selection summary renders. */
  async waitForSubscriptionSelection(timeoutMs = 15000): Promise<void> {
    await this.waitForText(/of \d+ subscriptions selected/, timeoutMs);
  }

  /** Wait until the summary reads "<selected> of <total> subscriptions selected". */
  async waitForSelectedSubscriptionCount(
    selected: number,
    total: number,
    timeoutMs = 15000,
  ): Promise<void> {
    await this.waitForText(
      new RegExp(`${selected} of ${total} subscriptions selected`),
      timeoutMs,
    );
  }

  /** Whether the summary reads "<selected> of <total> subscriptions selected". */
  hasSelectedSubscriptionCount(selected: number, total: number): boolean {
    return this.hasSelectionSummary(selected, total, "subscriptions");
  }

  /**
   * Whether any visible copy uses the AWS candidate noun, which a GCP flow must
   * never say — the negative half of the terminology assertions.
   */
  usesAccountWording(): boolean {
    return this.containsText(
      /accounts selected|Accounts Connected!|accounts under this Organization/,
    );
  }

  /** Toggle a discovered candidate's selection by the text of its tree row. */
  async toggleCandidate(idText: RegExp): Promise<void> {
    const item = await this.waitFor(() => this.treeItemByText(idText));
    const checkbox =
      item.querySelector<HTMLElement>('[role="checkbox"]') ?? item;
    await this.user.click(checkbox);
  }

  /** Toggle a discovered account's selection by its UID. */
  async toggleAccount(uid: string): Promise<void> {
    await this.toggleCandidate(new RegExp(uid));
  }

  /** Whether a discovered candidate is blocked (disabled, not selectable). */
  async isCandidateBlocked(idText: RegExp): Promise<boolean> {
    const item = await this.waitFor(() => this.treeItemByText(idText));
    return item.getAttribute("aria-disabled") === "true";
  }

  /** Whether a discovered account is blocked (disabled, not selectable). */
  async isAccountBlocked(uid: string): Promise<boolean> {
    return this.isCandidateBlocked(new RegExp(uid));
  }

  /** Type an alias into a candidate's tree-row alias input. */
  async setCandidateAlias(idText: RegExp, alias: string): Promise<void> {
    const item = await this.waitFor(() => this.treeItemByText(idText));
    const input = item.querySelector<HTMLInputElement>(
      "input:not([type='checkbox'])",
    );
    if (!input) throw new Error("no alias input for candidate");
    await this.user.fill(input, alias);
  }

  /**
   * What a candidate's row currently shows for its connection test: a settled
   * verdict, a spinner, or nothing yet.
   */
  candidateConnectionState(
    idText: RegExp,
  ): "success" | "error" | "testing" | "none" {
    const item = this.treeItemByText(idText);
    if (!item) return "none";
    if (item.querySelector('[aria-label="Success"]')) return "success";
    if (item.querySelector('[aria-label="Error"]')) return "error";
    if (item.querySelector('[aria-label="Loading"]')) return "testing";
    return "none";
  }

  /** Wait until a candidate's row settles on the given connection verdict. */
  async waitForCandidateConnectionState(
    idText: RegExp,
    state: "success" | "error",
    timeoutMs = 20000,
  ): Promise<void> {
    await this.waitFor(
      () => this.candidateConnectionState(idText) === state,
      timeoutMs,
    );
  }

  /** The `aria-checked` state of a tree row's checkbox (e.g. "mixed"). */
  candidateCheckboxState(idText: RegExp): string | null {
    const item = this.treeItemByText(idText);
    const checkbox = item?.querySelector<HTMLElement>('[role="checkbox"]');
    return checkbox?.getAttribute("aria-checked") ?? null;
  }

  async testConnections(): Promise<void> {
    await this.clickPrimary(/Test Connections/);
  }

  async skipValidation(): Promise<void> {
    const btn = await this.waitForButton(/Skip Connection Validation/);
    await this.user.click(btn);
  }

  async goBack(): Promise<void> {
    const btn = await this.waitForButton(/^\s*Back\s*$/);
    await this.user.click(btn);
  }

  /** Wait until every selected account has connected successfully. */
  async waitForAccountsConnected(timeoutMs = 20000): Promise<void> {
    await this.waitForText(/Accounts Connected!/, timeoutMs);
  }

  /** Wait until every selected project has connected successfully. */
  async waitForProjectsConnected(timeoutMs = 20000): Promise<void> {
    await this.waitForText(/Projects Connected!/, timeoutMs);
  }

  /** Wait until every selected subscription has connected successfully. */
  async waitForSubscriptionsConnected(timeoutMs = 20000): Promise<void> {
    await this.waitForText(/Subscriptions Connected!/, timeoutMs);
  }

  /** Wait until the flow reaches the connected / ready-to-scan state. */
  async waitForReadyToScan(timeoutMs = 20000): Promise<void> {
    await this.waitForText(/Accounts Connected!|ready to Scan/, timeoutMs);
  }

  /** Wait until the connection-test error alert surfaces (partial failure). */
  async waitForConnectionError(timeoutMs = 20000): Promise<void> {
    await this.waitForText(
      /problem connecting to some accounts|No accounts connected/,
      timeoutMs,
    );
  }

  /** Wait until the app has issued at least `n` connection-test requests. */
  async waitForConnectionAttempts(n: number, timeoutMs = 20000): Promise<void> {
    await this.waitFor(() => this.connectionCallCount >= n, timeoutMs);
  }

  /** Wait until the app has issued at least `n` apply requests. */
  async waitForApplyCount(n: number, timeoutMs = 20000): Promise<void> {
    await this.waitFor(() => this.applyCallCount >= n, timeoutMs);
  }

  // --- Wizard: launch step ------------------------------------------------

  /** Tick "launch an initial scan now" on the launch step's schedule form. */
  async enableInitialScan(): Promise<void> {
    const checkbox = await this.waitFor(() =>
      this.q(`[role="checkbox"][aria-label="${INITIAL_SCAN_LABEL}"]`),
    );
    await this.clickElement(checkbox);
  }

  /** Save the scan schedules and launch the initial scans (footer action). */
  async saveScheduleAndLaunch(): Promise<void> {
    await this.clickPrimary(/Save and launch scan/);
  }

  /** Wait until the schedules saved and the initial scans were launched. */
  async waitForLaunchComplete(timeoutMs = 20000): Promise<void> {
    await this.waitForText(
      /Scan schedules saved and initial scans launched/,
      timeoutMs,
    );
  }

  /** Wait for the "saved for some, failed for others" report. */
  async waitForPartialScheduleSave(
    saved: number,
    failed: number,
    timeoutMs = 20000,
  ): Promise<void> {
    await this.waitForText(
      new RegExp(
        `saved for ${saved} \\w+, but ${failed} \\w+ could not be updated`,
      ),
      timeoutMs,
    );
  }

  /** Wait for the report that no schedule could be saved at all. */
  async waitForScheduleSaveFailure(timeoutMs = 20000): Promise<void> {
    await this.waitForText(/could not be saved for/, timeoutMs);
  }

  /** Whether the reason the API gave for a failure reached the user. */
  hasScheduleFailureReason(reason: string): boolean {
    return this.containsText(new RegExp(reason));
  }

  /** Whether the wizard is still showing the launch step (it did not navigate). */
  isStillOnLaunchStep(): boolean {
    return this.containsText(/Scan Schedule/);
  }

  // --- Table: grouping + row actions --------------------------------------

  private get tableRows(): HTMLElement[] {
    return Array.from(this.container.querySelectorAll<HTMLElement>("tr"));
  }

  /** The table row (`<tr>`) whose text matches — a provider or group row. */
  private rowByText(text: RegExp): HTMLElement | null {
    return this.tableRows.find((r) => text.test(r.textContent ?? "")) ?? null;
  }

  private async waitForRow(
    text: RegExp,
    timeoutMs = 5000,
  ): Promise<HTMLElement> {
    return this.waitFor(() => this.rowByText(text), timeoutMs);
  }

  /** Whether a provider row addressed by its alias is present. */
  hasProviderRow(alias: string): boolean {
    return this.rowByText(new RegExp(alias)) !== null;
  }

  /** Wait until a provider row addressed by its alias is present. */
  async waitForProviderRow(alias: string): Promise<HTMLElement> {
    return this.waitForRow(new RegExp(alias));
  }

  /** Whether the organization group row is present. */
  hasOrganizationRow(name: string): boolean {
    return this.rowByText(new RegExp(name)) !== null;
  }

  /** Wait until the organization group row is present. */
  async waitForOrganizationRow(name: string): Promise<HTMLElement> {
    return this.waitForRow(new RegExp(name));
  }

  /** Wait until a node (OU / folder) group row is present. */
  async waitForNodeGroup(name: string): Promise<HTMLElement> {
    return this.waitForRow(new RegExp(name));
  }

  /** Whether a node group is labelled by its kind (e.g. "Organizational Unit"). */
  hasNodeKindLabel(label: string): boolean {
    return this.containsText(new RegExp(label));
  }

  /** Whether the organization row surfaces its total provider count. */
  hasProviderCount(count: number): boolean {
    return this.containsText(new RegExp(`${count} Providers`));
  }

  // --- Table: degraded-hierarchy notice ------------------------------------

  /** Wait until the notice for a failed hierarchy fetch surfaces. */
  async waitForDegradedHierarchyNotice(): Promise<void> {
    await this.waitForText(/Organization grouping is incomplete/);
  }

  /** Whether the degraded-hierarchy notice is present. */
  hasDegradedHierarchyNotice(): boolean {
    return this.containsText(/Organization grouping is incomplete/);
  }

  /** Whether the notice warns that providers may be ungrouped. */
  hasUngroupedProvidersNotice(): boolean {
    return this.containsText(/Some providers may appear ungrouped/);
  }

  /** Open the row-actions dropdown for the organization named `name`. */
  private async openActionsFor(name: string): Promise<void> {
    const trigger = await this.waitFor(() => {
      const row = this.rowByText(new RegExp(name));
      if (!row) return null;
      return (
        Array.from(row.querySelectorAll<HTMLButtonElement>("button")).find(
          (b) => /open actions menu/i.test(b.getAttribute("aria-label") ?? ""),
        ) ?? null
      );
    });
    await this.user.click(trigger);
  }

  /**
   * Dismiss the open row-actions menu and wait until it is gone. The menu is
   * modal, so leaving it open makes the next row's trigger click land on the
   * dismiss layer and the reader below re-read the previous row's items.
   */
  private async closeActionsMenu(): Promise<void> {
    await this.user.keyboard("{Escape}");
    await this.waitFor(() => this.q('[role="menu"]') === null);
  }

  /** The row-action labels offered for the organization named `name`. */
  async actionLabelsFor(name: string): Promise<string[]> {
    await this.openActionsFor(name);
    const menu = await this.waitFor(() => this.q('[role="menu"]'));
    const labels = Array.from(
      menu.querySelectorAll<HTMLElement>('[role="menuitem"]'),
    ).map((item) => item.textContent?.trim() ?? "");
    await this.closeActionsMenu();
    return labels;
  }

  /** Open the "Edit Organization Name" flow for the organization `name`. */
  async openEditNameFor(name: string): Promise<void> {
    await this.openActionsFor(name);
    await this.clickMenuItem(/Edit Organization Name/);
  }

  /** Open the "Update Credentials" flow for the organization `name`. */
  async openUpdateCredentialsFor(name: string): Promise<void> {
    await this.openActionsFor(name);
    await this.clickMenuItem(/Update Credentials/);
  }

  /** Open the "Delete Organization" flow for the organization `name`. */
  async openDeleteFor(name: string): Promise<void> {
    await this.openActionsFor(name);
    await this.clickMenuItem(/Delete Organization/);
  }

  /**
   * Open the delete flow for a folder — the GCP counterpart of `openDeleteFor`,
   * which says "Organizational Unit".
   */
  async openDeleteFolderFor(name: string): Promise<void> {
    await this.openActionsFor(name);
    await this.clickMenuItem(/Delete Folder/);
  }

  /** Open the delete flow for an Azure Management Group node. */
  async openDeleteManagementGroupFor(name: string): Promise<void> {
    await this.openActionsFor(name);
    await this.clickMenuItem(/Delete Management Group/);
  }

  /** Wait until the wizard re-opens on the AWS authentication step. */
  async waitForAuthenticationStep(): Promise<void> {
    await this.waitForText(
      /Amazon Web Services \(AWS\) \/ Authentication Details/,
    );
  }

  /** Whether the authentication step's primary button is present. */
  hasAuthenticateButton(): boolean {
    return this.buttonByText(/Authenticate/) !== null;
  }

  /** Whether a "Back" button is present. */
  hasBackButton(): boolean {
    return this.buttonByText(/^\s*Back\s*$/) !== null;
  }

  /** Wait until the delete-confirmation dialog surfaces. */
  async waitForDeleteConfirmation(): Promise<void> {
    await this.waitForText(/Are you absolutely sure/);
  }

  /** Whether the delete dialog shows its permanent-deletion warning. */
  hasDeleteWarning(): boolean {
    return this.hasDeleteWarningFor("organization");
  }

  /**
   * Whether the dialog warns about permanently deleting the given entity, whose
   * label follows the node kind ("folder" for GCP, "organizational unit" for AWS).
   */
  hasDeleteWarningFor(entityLabel: string): boolean {
    return this.containsText(
      new RegExp(`permanently delete this ${entityLabel}`),
    );
  }

  /** Whether the dialog states how many providers the deletion cascades to. */
  hasCascadeWarning(providerCount: number): boolean {
    return this.containsText(
      new RegExp(`cascade to its ${providerCount} providers?`),
    );
  }

  /** Confirm the delete-organization dialog. */
  async confirmDelete(): Promise<void> {
    await this.clickButton(/^\s*Delete\s*$/);
  }

  /** Wait until the app has issued the given request (defaults to at least one). */
  protected async waitForRequest(
    method: string,
    pathIncludes: string,
    count = 1,
    timeoutMs = 15000,
  ): Promise<void> {
    await this.waitFor(
      () => this.countRequests(method, pathIncludes) >= count,
      timeoutMs,
    );
  }

  /** Wait until the app has PATCHed (renamed) the given organization. */
  async waitForOrganizationRename(orgId: string): Promise<void> {
    await this.waitForRequest("PATCH", `/organizations/${orgId}`);
  }

  /** Wait until the app has issued the DELETE for the given organization. */
  async waitForOrganizationDelete(orgId: string): Promise<void> {
    await this.waitForRequest("DELETE", `/organizations/${orgId}`);
  }

  /** Wait until the app has issued the DELETE for the given hierarchy node. */
  async waitForNodeDelete(nodeId: string): Promise<void> {
    await this.waitForRequest("DELETE", `/organization-nodes/${nodeId}`);
  }

  /** How many times the app polled a task (`GET /tasks/:id`). */
  get taskPollCount(): number {
    return this.countRequests("GET", "/tasks/");
  }

  /** Wait until the app polled the deletion task the API answered 202 with. */
  async waitForTaskPoll(taskIdPrefix = ""): Promise<void> {
    await this.waitForRequest("GET", `/tasks/${taskIdPrefix}`);
  }

  /**
   * Wait until the deletion is reported as accepted — not "removed successfully",
   * since the polled task completes on dispatch, not on completion.
   */
  async waitForDeletionAccepted(timeoutMs = 15000): Promise<void> {
    await this.waitForText(/Deletion started/, timeoutMs);
  }

  /** Whether any copy overclaims a deletion that is only under way. */
  claimsDeletionFinished(): boolean {
    return this.containsText(/removed successfully|was deleted/);
  }

  /** Wait until a failed deletion task is reported instead of a false success. */
  async waitForDeletionFailure(timeoutMs = 15000): Promise<void> {
    await this.waitForText(/Deletion did not complete/, timeoutMs);
  }

  // --- Table: edit-name modal ---------------------------------------------

  private get editNameInput(): HTMLInputElement | null {
    return this.q("#edit-name-input") as HTMLInputElement | null;
  }

  /** Wait until the inline edit-name modal is open. */
  async waitForEditNameModal(): Promise<void> {
    await this.waitForText(
      /If left blank, Prowler will use the name stored in AWS/,
    );
  }

  async fillEditName(value: string): Promise<void> {
    const input = await this.waitFor(() => this.editNameInput);
    await this.user.fill(input, value);
  }

  /** Save the inline edit-name modal. */
  async saveName(): Promise<void> {
    await this.clickButton(/^\s*Save\s*$/);
  }
}
