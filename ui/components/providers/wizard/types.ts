import { OrgSetupPhase, OrgWizardStep } from "@/types/organizations";
import { ProviderWizardMode } from "@/types/provider-wizard";
import { ProviderType } from "@/types/providers";

export interface ProviderWizardInitialData {
  providerId: string;
  providerType: ProviderType;
  providerUid: string;
  providerAlias: string | null;
  secretId?: string | null;
  via?: string | null;
  mode?: ProviderWizardMode;
}

export const ORG_WIZARD_INTENT = {
  FULL: "full",
  EDIT_NAME: "edit-name",
  EDIT_CREDENTIALS: "edit-credentials",
} as const;

export type OrgWizardIntent =
  (typeof ORG_WIZARD_INTENT)[keyof typeof ORG_WIZARD_INTENT];

export interface OrgWizardInitialData {
  organizationId: string;
  organizationName: string;
  externalId: string;
  targetStep: OrgWizardStep;
  targetPhase: OrgSetupPhase;
  intent?: OrgWizardIntent;
}
