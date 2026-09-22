import {
  ORG_SETUP_PHASE,
  ORG_WIZARD_STEP,
  OrgSetupPhase,
  OrgWizardStep,
} from "@/types/organizations";
import {
  PROVIDER_WIZARD_MODE,
  PROVIDER_WIZARD_STEP,
  ProviderWizardMode,
  ProviderWizardStep,
} from "@/types/provider-wizard";
import type { ProviderType } from "@/types/providers";

import {
  AWS_PROVIDER_WIZARD_STEPS,
  PROVIDER_WIZARD_STEPS,
} from "./wizard-stepper";

const UPDATE_MODE_WIZARD_STEPS = PROVIDER_WIZARD_STEPS.slice(
  0,
  PROVIDER_WIZARD_STEP.LAUNCH,
);

interface ProviderWizardStepperInput {
  mode: ProviderWizardMode;
  providerType: ProviderType | null;
  currentStep: ProviderWizardStep;
}

/** Rows for the provider-flow stepper plus the offset that maps `currentStep` onto them. */
export function getProviderWizardStepper({
  mode,
  providerType,
  currentStep,
}: ProviderWizardStepperInput) {
  if (mode === PROVIDER_WIZARD_MODE.UPDATE) {
    return { steps: UPDATE_MODE_WIZARD_STEPS, stepOffset: 0 };
  }
  if (providerType === "aws") {
    // CONNECT stays on the first row; TEST and LAUNCH shift up one.
    const stepOffset = currentStep >= PROVIDER_WIZARD_STEP.TEST ? -1 : 0;
    return { steps: AWS_PROVIDER_WIZARD_STEPS, stepOffset };
  }
  return { steps: PROVIDER_WIZARD_STEPS, stepOffset: 0 };
}

export function getOrganizationsStepperOffset(
  currentStep: OrgWizardStep,
  setupPhase: OrgSetupPhase,
) {
  if (currentStep === ORG_WIZARD_STEP.SETUP) {
    return setupPhase === ORG_SETUP_PHASE.ACCESS ? 1 : 0;
  }

  return 1;
}

export function getProviderWizardModalTitle(mode: ProviderWizardMode) {
  if (mode === PROVIDER_WIZARD_MODE.UPDATE) {
    return "Update Provider Credentials";
  }

  return "Adding A Provider";
}

export function getProviderWizardDocsDestination(docsLink: string) {
  const destinationLabelMap: Record<string, string> = {
    "aws-organizations": "AWS Organizations",
    "azure-management-groups": "Azure Organizations",
    "gcp-organizations": "GCP Organizations",
    aws: "AWS",
    azure: "Azure",
    m365: "Microsoft 365",
    microsoft365: "Microsoft 365",
    gcp: "GCP",
    k8s: "Kubernetes",
    kubernetes: "Kubernetes",
    github: "GitHub",
    iac: "IaC",
    image: "Image",
    oci: "Oracle Cloud",
    oraclecloud: "Oracle Cloud",
    mongodbatlas: "MongoDB Atlas",
    alibabacloud: "Alibaba Cloud",
    cloudflare: "Cloudflare",
    openstack: "OpenStack",
    googleworkspace: "Google Workspace",
    vercel: "Vercel",
    okta: "Okta",
    help: "Provider",
    providers: "Provider",
  };

  const stripUrlShapePrefix = (segment: string) =>
    segment
      .replace(/^getting-started-/, "")
      .replace(/^provider-/, "")
      .replace(/^prowler-cloud-/, "");

  try {
    const parsed = new URL(docsLink);
    // Labels for method-specific credentials-step deep links. Keyed by the
    // docs URL slug (which can differ from the wizard provider key — e.g.
    // the docs use `microsoft365` while the wizard uses `m365`). Providers
    // whose credentials-step URL is the general step anchor are omitted
    // here and fall back to the provider label ("AWS", "Google Workspace",
    // etc.) via the `destinationLabelMap` below.
    const docsSectionLabelMap: Record<string, string> = {
      "aws#assume-role-recommended": "AWS Assume Role",
      "aws#credentials-static-access-keys": "AWS Credentials",
      "microsoft365#application-certificate-authentication-recommended":
        "M365 Certificate",
      "microsoft365#application-client-secret-authentication":
        "M365 Client Secret",
      "alibabacloud#ram-role-assumption-recommended": "Alibaba Cloud RAM Role",
      "alibabacloud#credentials-static-access-keys":
        "Alibaba Cloud Credentials",
      "cloudflare#user-api-token-authentication-recommended":
        "Cloudflare API Token",
      "cloudflare#api-key-and-email-authentication-legacy":
        "Cloudflare API Key",
    };
    const pathSegments = parsed.pathname
      .split("/")
      .filter((segment) => segment.length > 0);
    const lastSegment = pathSegments.at(-1);

    if (!lastSegment) {
      return parsed.hostname;
    }

    // For docs URLs shaped as `/user-guide/providers/<slug>/<page>` the
    // provider slug is the segment right after `providers`, not the last one
    // (which is a page name like `authentication` or `getting-started-<X>`).
    // Prefer that when present so pages like
    // `/user-guide/providers/aws/authentication` map to "AWS" instead of
    // the meaningless title-cased fallback ("Authentication").
    const providersIndex = pathSegments.indexOf("providers");
    const providerSlugFromPath =
      providersIndex >= 0 && providersIndex + 1 < pathSegments.length
        ? pathSegments[providersIndex + 1]
        : undefined;

    if (providerSlugFromPath && parsed.hash) {
      const sectionLabel =
        docsSectionLabelMap[`${providerSlugFromPath}${parsed.hash}`];
      if (sectionLabel) return sectionLabel;
    }

    for (const candidate of [providerSlugFromPath, lastSegment]) {
      if (!candidate) continue;
      const compact = stripUrlShapePrefix(candidate);
      const mapped = destinationLabelMap[compact];
      if (mapped) return mapped;
    }

    return stripUrlShapePrefix(lastSegment)
      .split("-")
      .map((word) =>
        word.length === 0 ? word : word[0].toUpperCase() + word.slice(1),
      )
      .join(" ");
  } catch {
    return docsLink;
  }
}
