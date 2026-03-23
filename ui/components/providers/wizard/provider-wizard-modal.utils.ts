import {
  ORG_SETUP_PHASE,
  ORG_WIZARD_STEP,
  OrgSetupPhase,
  OrgWizardStep,
} from "@/types/organizations";
import {
  PROVIDER_WIZARD_MODE,
  ProviderWizardMode,
} from "@/types/provider-wizard";

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

  return "Adding A Cloud Provider";
}

export function getProviderWizardDocsDestination(docsLink: string) {
  const destinationLabelMap: Record<string, string> = {
    "aws-organizations": "AWS Organizations",
    aws: "AWS",
    azure: "Azure",
    m365: "Microsoft 365",
    gcp: "GCP",
    k8s: "Kubernetes",
    kubernetes: "Kubernetes",
    github: "GitHub",
    iac: "IaC",
    oraclecloud: "Oracle Cloud",
    mongodbatlas: "MongoDB Atlas",
    alibabacloud: "Alibaba Cloud",
    cloudflare: "Cloudflare",
    openstack: "OpenStack",
    help: "Cloud Provider",
  };

  try {
    const parsed = new URL(docsLink);
    const pathSegments = parsed.pathname
      .split("/")
      .filter((segment) => segment.length > 0);
    const lastSegment = pathSegments.at(-1);

    if (!lastSegment) {
      return parsed.hostname;
    }

    const compactDestination = lastSegment
      .replace(/^provider-/, "")
      .replace(/^prowler-cloud-/, "");
    const mappedDestination = destinationLabelMap[compactDestination];

    if (mappedDestination) {
      return mappedDestination;
    }

    return compactDestination
      .split("-")
      .map((word) =>
        word.length === 0 ? word : word[0].toUpperCase() + word.slice(1),
      )
      .join(" ");
  } catch {
    return docsLink;
  }
}
