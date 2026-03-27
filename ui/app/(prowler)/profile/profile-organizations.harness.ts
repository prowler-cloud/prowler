import { page } from "vitest/browser";

/**
 * Harness for testing the organizations section
 * of the User Profile page.
 */
export class ProfileOrganizationsHarness {
  // ── Card-level ──

  cardTitle() {
    return page.getByText("Organizations", { exact: true });
  }

  noMembershipsMessage() {
    return page.getByText("No memberships found.");
  }

  createButton() {
    return page.getByRole("button", { name: /create organization/i });
  }

  // ── Org-row locators ──

  activeBadge() {
    return page.getByText("Active", { exact: true }).first();
  }

  activeBadges() {
    return page.getByText("Active", { exact: true });
  }

  switchButtons() {
    return page.getByRole("button", { name: /^switch$/i });
  }

  switchButtonAt(index: number) {
    return this.switchButtons().nth(index);
  }

  editButton() {
    return page.getByRole("button", { name: /^edit$/i });
  }

  editButtons() {
    return page.getByRole("button", { name: /^edit$/i });
  }

  deleteButton() {
    return page.getByRole("button", { name: /^delete$/i });
  }

  deleteButtons() {
    return page.getByRole("button", { name: /^delete$/i });
  }

  orgName(name: string) {
    return page.getByText(name);
  }

  // ── Modal / dialog ──

  dialog() {
    return page.getByRole("dialog");
  }

  alertDialog() {
    return page.getByRole("alertdialog");
  }

  confirmationTitle() {
    return page.getByText("Confirm organization switch");
  }

  confirmButton() {
    return page.getByRole("button", { name: /confirm/i });
  }

  cancelButton() {
    return page.getByRole("button", { name: /cancel/i });
  }

  hiddenTenantInput() {
    return page
      .getByRole("alertdialog")
      .element()
      .querySelector('input[name="tenantId"]');
  }

  // ── Form locators ──

  editNameInput() {
    return page.getByPlaceholder("Enter the new name");
  }

  deleteConfirmInput(tenantName: string) {
    return page.getByPlaceholder(tenantName);
  }

  targetTenantSelect() {
    return page.getByRole("combobox");
  }

  switchToAfterDeletionText() {
    return page.getByText(/switch to after deletion/i);
  }

  submitButton(text: RegExp = /create|delete/i) {
    return page.getByRole("button", { name: text });
  }

  currentNameDisplay(name: string) {
    return page.getByText(`Current name: ${name}`);
  }

  // ── Actions ──

  async clickSwitchOnFirstAvailable() {
    await this.switchButtons().first().click();
  }

  async clickSwitchAt(index: number) {
    await this.switchButtonAt(index).click();
  }

  async cancelSwitch() {
    await this.cancelButton().click();
  }

  async openEditModal() {
    await this.editButton().click();
  }

  async openEditModalAt(index: number) {
    await this.editButtons().nth(index).click();
  }

  async openDeleteModalAt(index: number) {
    await this.deleteButtons().nth(index).click();
  }

  async openSwitchModalAt(index: number) {
    await this.switchButtons().nth(index).click();
  }

  async fillDeleteConfirmation(tenantName: string, value: string) {
    await this.deleteConfirmInput(tenantName).fill(value);
  }

  async cancel() {
    await this.cancelButton().click();
  }

  async submitDelete() {
    await this.submitButton(/delete/i).click();
  }

  async selectTargetTenant(name: string) {
    await this.targetTenantSelect().click();
    await this.orgName(name).last().click();
  }
}
