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

export class ProvidersPageHarness extends BrowserHarness<OrgFixture> {
  get applyCallCount(): number {
    return this.countRequests("POST", "/apply");
  }

  private get connectionCallCount(): number {
    return this.countRequests("POST", "/connection");
  }

  /** How many times the page fetched the organization list over HTTP. */
  get organizationFetchCount(): number {
    return this.countRequests("GET", "/organizations");
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

  /** How many scans were launched (one per provider whose schedule saved). */
  get scanLaunchCount(): number {
    return this.countRequests("POST", "/scans");
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

  /** Click a method card in the AWS/GCP method selector by its title. */
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

  private selectedCountText(): string {
    return (
      this.container.textContent?.match(/\d+ of \d+ accounts selected/)?.[0] ??
      ""
    );
  }

  async waitForSelectionTree(): Promise<HTMLElement> {
    return this.waitFor(() => this.tree);
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
    return new RegExp(`${selected} of ${total} accounts selected`).test(
      this.selectedCountText(),
    );
  }

  /** Toggle a discovered account's selection by its UID. */
  async toggleAccount(uid: string): Promise<void> {
    const item = await this.waitFor(() => this.treeItemByText(new RegExp(uid)));
    const checkbox =
      item.querySelector<HTMLElement>('[role="checkbox"]') ?? item;
    await this.user.click(checkbox);
  }

  /** Whether a discovered account is blocked (disabled, not selectable). */
  async isAccountBlocked(uid: string): Promise<boolean> {
    const item = await this.waitFor(() => this.treeItemByText(new RegExp(uid)));
    return item.getAttribute("aria-disabled") === "true";
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

  /** The row-action labels offered for the organization named `name`. */
  async actionLabelsFor(name: string): Promise<string[]> {
    await this.openActionsFor(name);
    await this.waitFor(() => this.q('[role="menuitem"]'));
    return Array.from(
      document.querySelectorAll<HTMLElement>('[role="menuitem"]'),
    ).map((item) => item.textContent?.trim() ?? "");
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
    return this.containsText(/permanently delete this organization/);
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

  /** How many times the app polled a task (`GET /tasks/:id`). */
  get taskPollCount(): number {
    return this.countRequests("GET", "/tasks/");
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
