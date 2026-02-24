import { describe, expect, it } from "vitest";

import { ORG_SETUP_PHASE, ORG_WIZARD_STEP } from "@/types/organizations";
import { PROVIDER_WIZARD_MODE } from "@/types/provider-wizard";

import {
  getOrganizationsStepperOffset,
  getProviderWizardModalTitle,
} from "./provider-wizard-modal.utils";

describe("getOrganizationsStepperOffset", () => {
  it("keeps step 1 active during organization details", () => {
    const offset = getOrganizationsStepperOffset(
      ORG_WIZARD_STEP.SETUP,
      ORG_SETUP_PHASE.DETAILS,
    );

    expect(offset).toBe(0);
  });

  it("moves to step 2 during credentials phase", () => {
    const offset = getOrganizationsStepperOffset(
      ORG_WIZARD_STEP.SETUP,
      ORG_SETUP_PHASE.ACCESS,
    );

    expect(offset).toBe(1);
  });

  it("uses step 2+ offset for later wizard steps", () => {
    const offset = getOrganizationsStepperOffset(
      ORG_WIZARD_STEP.VALIDATE,
      ORG_SETUP_PHASE.DETAILS,
    );

    expect(offset).toBe(1);
  });
});

describe("getProviderWizardModalTitle", () => {
  it("returns add title for add mode", () => {
    const title = getProviderWizardModalTitle(PROVIDER_WIZARD_MODE.ADD);

    expect(title).toBe("Adding A Cloud Provider");
  });

  it("returns update title for update mode", () => {
    const title = getProviderWizardModalTitle(PROVIDER_WIZARD_MODE.UPDATE);

    expect(title).toBe("Update Provider Credentials");
  });
});
