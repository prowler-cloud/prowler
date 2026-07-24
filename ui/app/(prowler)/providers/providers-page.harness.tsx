/**
 * Page-level test harness for the providers page + organizations onboarding
 * wizard (Vitest Browser Mode).
 *
 * Mirrors the attack-paths harness pattern: it owns mounting and MSW wiring and
 * exposes semantic methods so tests interact through intent ("choose AWS
 * Organizations", "authenticate", "test connections") rather than raw
 * selectors. Discovery/connection polling is real (MSW returns terminal states
 * on the first poll), so flow methods wait on the resulting UI.
 */

import { SessionProvider } from "next-auth/react";
import { vi } from "vitest";
import { userEvent } from "vitest/browser";
import { render } from "vitest-browser-react";

import { handlersForOrganizations } from "@/__tests__/msw/handlers/organizations";
import { NODE_KIND } from "@/__tests__/msw/handlers/organizations.fixtures";
import type {
  FixtureNode,
  FixtureOrganization,
  FixtureProvider,
  OrgFixture,
} from "@/__tests__/msw/handlers/organizations.fixtures";
import { worker } from "@/__tests__/msw/worker";
import { ProvidersAccountsView } from "@/components/providers/providers-accounts-view";
import {
  ADD_PROVIDER_SEARCH_PARAM,
  ADD_PROVIDER_SEARCH_VALUE,
} from "@/lib/providers-navigation";
import { isCloud } from "@/lib/shared/env";
import type { ProviderProps } from "@/types";
import type {
  OrganizationResource,
  OrganizationType,
  OrganizationUnitResource,
} from "@/types/organizations";
import {
  PROVIDERS_ROW_TYPE,
  type ProvidersProviderRow,
  type ProvidersTableRow,
} from "@/types/providers-table";

import { buildProvidersTableRows } from "./providers-page.utils";

const TENANT_ID = "11111111-2222-4333-8444-555555555555";
const TS = "2026-07-01T10:00:00Z";

interface MountOptions {
  /** Seed `?addProvider=true` so the wizard opens on mount. Default true. */
  openWizard?: boolean;
}

export class ProvidersPageHarness {
  readonly user = userEvent;
  /** Every request MSW sees during the test, for behavioral assertions. */
  readonly requestLog: Array<{ method: string; url: string }> = [];

  constructor(readonly fixture: OrgFixture) {}

  countRequests(method: string, pathIncludes: string): number {
    return this.requestLog.filter(
      (r) => r.method === method && r.url.includes(pathIncludes),
    ).length;
  }

  get applyCallCount(): number {
    return this.countRequests("POST", "/apply");
  }

  get connectionCallCount(): number {
    return this.countRequests("POST", "/connection");
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

  mount({ openWizard = true }: MountOptions = {}): void {
    this.seedWizardUrl(openWizard);
    worker.use(...handlersForOrganizations(this.fixture));
    worker.events.removeAllListeners();
    worker.events.on("request:start", ({ request }) => {
      this.requestLog.push({ method: request.method, url: request.url });
    });

    const session = {
      tenantId: TENANT_ID,
      accessToken: "test-access-token",
      expires: "2999-01-01T00:00:00Z",
    };

    // Single source of truth: the runtime-config island (seeded by the
    // `seedRuntimeConfig` fixture) drives both `isCloud()` deep in the tree and
    // the top-level prop, exactly as `providers/page.tsx` derives it in prod.
    const cloud = isCloud();
    const providers = this.buildProviderProps();
    const rows = this.buildTableRows(cloud);

    render(
      <SessionProvider session={session as never}>
        <ProvidersAccountsView
          isCloud={cloud}
          filters={[]}
          providers={providers}
          rows={rows}
          providerGroups={[]}
        />
      </SessionProvider>,
    );
  }

  // --- Providers-page data (fixture → table props) ------------------------
  //
  // The providers page computes its grouped rows server-side in
  // `loadProvidersAccountsViewData` (which browser mode cannot mount). We
  // reproduce that here: convert the fixture's seeded world into the wire
  // shapes and run the real `buildProvidersTableRows` transform, so the
  // mounted client table renders exactly the rows production would. Onboarding
  // fixtures seed no providers, so this yields `[]` (empty state + wizard),
  // preserving the flow tests' behaviour.

  private toProviderRow(provider: FixtureProvider): ProvidersProviderRow {
    return {
      id: provider.id,
      type: "providers",
      rowType: PROVIDERS_ROW_TYPE.PROVIDER,
      attributes: {
        provider: provider.provider,
        is_dynamic: false,
        uid: provider.uid,
        alias: provider.alias,
        status: "completed",
        resources: 0,
        connection: {
          connected: provider.connected ?? false,
          last_checked_at: TS,
        },
        scanner_args: {
          only_logs: false,
          excluded_checks: [],
          aws_retries_max_attempts: 3,
        },
        inserted_at: TS,
        updated_at: TS,
        created_by: { object: "user", id: "user-1" },
      },
      relationships: {
        secret: { data: { type: "secrets", id: `secret-${provider.id}` } },
        provider_groups: { meta: { count: 0 }, data: [] },
      },
      groupNames: [],
      hasSchedule: false,
    };
  }

  private toOrganizationResource(
    org: FixtureOrganization,
  ): OrganizationResource {
    return {
      id: org.id,
      type: "organizations",
      attributes: {
        name: org.name,
        org_type: org.orgType as OrganizationType,
        external_id: org.externalId,
        metadata: {},
        root_external_id: org.rootExternalId,
      },
      relationships: {
        providers: {
          data: org.providerIds.map((id) => ({ id, type: "providers" })),
        },
        organizational_units: {
          data: org.nodeIds.map((id) => ({ id, type: "organizational-units" })),
        },
      },
    };
  }

  private toOrganizationUnitResource(
    node: FixtureNode,
  ): OrganizationUnitResource {
    return {
      id: node.id,
      type: "organizational-units",
      attributes: {
        name: node.name,
        external_id: node.externalId,
        parent_external_id: node.parentExternalId,
        metadata: {},
      },
      relationships: {
        organization: {
          data: { id: node.organizationId, type: "organizations" },
        },
        providers: {
          data: node.providerIds.map((id) => ({ id, type: "providers" })),
        },
      },
    };
  }

  private buildProviderProps(): ProviderProps[] {
    return this.fixture.providers.map((provider) =>
      this.toProviderRow(provider),
    );
  }

  private buildTableRows(cloud: boolean): ProvidersTableRow[] {
    // The current (AWS-only) grouping transform consumes `/organizational-units`;
    // GCP folders are ignored here exactly as production ignores them today.
    return buildProvidersTableRows({
      isCloud: cloud,
      organizations: this.fixture.organizations.map((org) =>
        this.toOrganizationResource(org),
      ),
      organizationUnits: this.fixture.nodes
        .filter((node) => node.kind === NODE_KIND.ORGANIZATIONAL_UNIT)
        .map((node) => this.toOrganizationUnitResource(node)),
      providers: this.fixture.providers.map((provider) =>
        this.toProviderRow(provider),
      ),
    });
  }

  // --- Low-level DOM

  private get container(): HTMLElement {
    return document.body;
  }

  private containsText(pattern: RegExp): boolean {
    return pattern.test(this.container.textContent ?? "");
  }

  private q(selector: string): HTMLElement | null {
    return this.container.querySelector<HTMLElement>(selector);
  }

  private byRoleName(
    role: string,
    name: RegExp,
    scope: ParentNode = document,
  ): HTMLElement | null {
    const nodes = Array.from(
      scope.querySelectorAll<HTMLElement>(`[role="${role}"]`),
    );
    return (
      nodes.find((el) => name.test(el.textContent ?? "")) ??
      // Buttons expose their role implicitly.
      Array.from(scope.querySelectorAll<HTMLElement>("button")).find(
        (el) =>
          el.getAttribute("role") === role && name.test(el.textContent ?? ""),
      ) ??
      null
    );
  }

  private buttonByText(
    name: RegExp,
    scope: ParentNode = document,
  ): HTMLButtonElement | null {
    return (
      Array.from(scope.querySelectorAll<HTMLButtonElement>("button")).find(
        (b) => name.test(b.textContent ?? ""),
      ) ?? null
    );
  }

  private inputByName(name: string): HTMLInputElement | null {
    return this.q(`input[name="${name}"]`) as HTMLInputElement | null;
  }

  // --- Sync helpers (private) ---------------------------------------------

  private async waitFor<T>(
    fn: () => T | null | undefined | false,
    timeoutMs = 5000,
  ): Promise<T> {
    return vi.waitFor(
      () => {
        const v = fn();
        if (!v) throw new Error("waitFor predicate not yet truthy");
        return v;
      },
      { timeout: timeoutMs, interval: 30 },
    ) as Promise<T>;
  }

  private async waitForText(pattern: RegExp, timeoutMs = 5000): Promise<void> {
    await this.waitFor(() => this.containsText(pattern), timeoutMs);
  }

  private async waitForButton(
    name: RegExp,
    timeoutMs = 5000,
  ): Promise<HTMLButtonElement> {
    return this.waitFor(() => {
      const btn = this.buttonByText(name);
      return btn && !btn.disabled ? btn : null;
    }, timeoutMs);
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

  /** Click a dropdown/menu item (rendered in a Radix portal) by its label. */
  private async clickMenuItem(name: RegExp): Promise<void> {
    const item = await this.waitFor(() => this.byRoleName("menuitem", name));
    await this.user.click(item);
  }

  private async clickButton(name: RegExp): Promise<void> {
    const btn = await this.waitForButton(name);
    await this.user.click(btn);
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
  async waitForRequest(
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
