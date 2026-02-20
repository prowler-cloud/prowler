import { describe, expect, it } from "vitest";

import { ORG_SETUP_PHASE, ORG_WIZARD_STEP } from "@/types/organizations";

import { getOrganizationsStepperOffset } from "./provider-wizard-modal.utils";

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
