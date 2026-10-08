import { ProviderType } from "./providers";

export const PROVIDER_WIZARD_STEP = {
  CONNECT: 0,
  CREDENTIALS: 1,
  TEST: 2,
  LAUNCH: 3,
} as const;

export type ProviderWizardStep =
  (typeof PROVIDER_WIZARD_STEP)[keyof typeof PROVIDER_WIZARD_STEP];

export const PROVIDER_WIZARD_MODE = {
  ADD: "add",
  UPDATE: "update",
} as const;

export type ProviderWizardMode =
  (typeof PROVIDER_WIZARD_MODE)[keyof typeof PROVIDER_WIZARD_MODE];

export interface ProviderWizardIdentity {
  id: string;
  type: ProviderType;
  uid: string | null;
  alias: string | null;
}

export type AwsConnectDraftValues = Record<string, string>;

/** Which panel the AWS connect step shows: the access forms or the teammate invitation. */
export const AWS_CONNECT_PANEL = {
  ACCESS: "access",
  INVITE: "invite",
} as const;

export type AwsConnectPanel =
  (typeof AWS_CONNECT_PANEL)[keyof typeof AWS_CONNECT_PANEL];

/** What the AWS connect step typed so far; in memory only, gone with the wizard. */
export interface AwsConnectDraft {
  method: string;
  panel: AwsConnectPanel;
  roleValues: AwsConnectDraftValues;
  keysValues: AwsConnectDraftValues;
}
