import { describe, expect, it } from "vitest";

import { ORG_SETUP_PHASE, ORG_WIZARD_STEP } from "@/types/organizations";
import { PROVIDER_WIZARD_MODE } from "@/types/provider-wizard";

import {
  getOrganizationsStepperOffset,
  getProviderWizardDocsDestination,
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

    expect(title).toBe("Adding A Provider");
  });

  it("returns update title for update mode", () => {
    const title = getProviderWizardModalTitle(PROVIDER_WIZARD_MODE.UPDATE);

    expect(title).toBe("Update Provider Credentials");
  });
});

describe("getProviderWizardDocsDestination", () => {
  it("returns a compact provider label for short provider docs links", () => {
    const destination = getProviderWizardDocsDestination(
      "https://goto.prowler.com/provider-aws",
    );

    expect(destination).toBe("AWS");
  });

  it("returns a compact provider label for deep-linked getting-started URLs", () => {
    const destination = getProviderWizardDocsDestination(
      "https://docs.prowler.com/user-guide/providers/aws/getting-started-aws",
    );

    expect(destination).toBe("AWS");
  });

  it("ignores a #authentication anchor when deriving the label", () => {
    // The credentials step falls back to a shortlink + anchor for providers
    // without a dedicated auth page (Kubernetes). The label shown in the
    // modal header must stay the provider name, not shift with the anchor.
    const destination = getProviderWizardDocsDestination(
      "https://goto.prowler.com/provider-k8s#authentication",
    );

    expect(destination).toBe("Kubernetes");
  });

  it("derives the provider label from the dedicated authentication docs URL", () => {
    // On the credentials step providers with a standalone authentication.mdx
    // (all except Kubernetes) point to `/providers/<slug>/authentication`.
    // The label must come from the `<slug>` segment, not from the trailing
    // "authentication" page name.
    const destination = getProviderWizardDocsDestination(
      "https://docs.prowler.com/user-guide/providers/aws/authentication",
    );

    expect(destination).toBe("AWS");
  });

  it("maps the OCI docs slug to the Oracle Cloud label", () => {
    // The provider is called `oraclecloud` in the wizard but the docs path
    // uses the `oci` slug, so the parser must know both refer to the same
    // provider.
    const destination = getProviderWizardDocsDestination(
      "https://docs.prowler.com/user-guide/providers/oci/authentication",
    );

    expect(destination).toBe("Oracle Cloud");
  });

  it("maps the microsoft365 docs slug to the Microsoft 365 label", () => {
    // Same shape: the wizard's `m365` maps to the `microsoft365` folder in
    // docs, so the parser must recognise the folder slug as the provider.
    const destination = getProviderWizardDocsDestination(
      "https://docs.prowler.com/user-guide/providers/microsoft365/authentication",
    );

    expect(destination).toBe("Microsoft 365");
  });

  it("returns a compact destination label for long docs links", () => {
    const destination = getProviderWizardDocsDestination(
      "https://docs.prowler.com/user-guide/tutorials/prowler-cloud-aws-organizations",
    );

    expect(destination).toBe("AWS Organizations");
  });
});
