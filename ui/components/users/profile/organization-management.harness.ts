import { page } from "vitest/browser";

export class OrganizationManagementHarness {
  // Locators
  createButton() {
    return page.getByRole("button", { name: /create organization/i });
  }

  deleteButton() {
    return page.getByRole("button", { name: /delete/i });
  }

  nameInput() {
    return page.getByLabelText(/organization name/i);
  }

  confirmInput() {
    return page.getByPlaceholder(/.+/);
  }

  targetTenantSelect() {
    return page.getByRole("combobox");
  }

  submitButton(text: RegExp = /create|delete/i) {
    return page.getByRole("button", { name: text });
  }

  cancelButton() {
    return page.getByRole("button", { name: /cancel/i });
  }

  modal() {
    return page.getByRole("alertdialog");
  }

  dialog() {
    return page.getByRole("dialog");
  }

  // Actions
  async openCreateModal() {
    await this.createButton().click();
  }

  async openDeleteModal() {
    await this.deleteButton().click();
  }

  async fillName(name: string) {
    await this.nameInput().fill(name);
  }

  async fillConfirmation(name: string) {
    await this.confirmInput().fill(name);
  }

  async submit(text?: RegExp) {
    await this.submitButton(text).click();
  }

  async cancel() {
    await this.cancelButton().click();
  }
}
