import { page } from "vitest/browser";

/**
 * Harness for testing the organization switch flow
 * on the User Profile page.
 */
export class ProfileSwitchTenantHarness {
  // Organization rows
  activeBadge() {
    return page.getByText("Active", { exact: true }).first();
  }

  switchButtons() {
    return page.getByRole("button", { name: /switch/i });
  }

  orgName(name: string) {
    return page.getByText(name);
  }

  // Confirmation dialog
  confirmationDialog() {
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

  // Actions
  async clickSwitchOnFirstAvailable() {
    await this.switchButtons().first().click();
  }

  async confirmSwitch() {
    await this.confirmButton().click();
  }

  async cancelSwitch() {
    await this.cancelButton().click();
  }
}
