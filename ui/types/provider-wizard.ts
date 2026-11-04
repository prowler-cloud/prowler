import { ProviderType } from "./providers";

// Connect registers the account, stores its credentials and tests them in one step.
export const PROVIDER_WIZARD_STEP = {
  CONNECT: 0,
  LAUNCH: 1,
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

export type ConnectDraftValues = Record<string, string>;

/** Which panel the connect step shows: the access forms or the teammate invitation. */
export const CONNECT_PANEL = {
  ACCESS: "access",
  INVITE: "invite",
} as const;

export type ConnectPanel = (typeof CONNECT_PANEL)[keyof typeof CONNECT_PANEL];

/** What the connect step typed so far; in memory only, gone with the wizard. */
export interface ConnectDraft {
  providerType: string;
  /** The picked access method; null for a provider with a single one. */
  method: string | null;
  panel: ConnectPanel;
  /** Values per access method, so switching methods never mixes their fields. */
  values: Record<string, ConnectDraftValues>;
}
