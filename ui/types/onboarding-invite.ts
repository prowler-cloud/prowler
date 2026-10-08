// Query param the API can read to tell where an invitation was sent from.
export const INVITATION_SOURCE_PARAM = "source";

export const INVITATION_SOURCE = {
  ONBOARDING: "onboarding",
  // Sent from the add-provider wizard by a user who cannot connect the account.
  PROVIDER_CONNECT: "provider_connect",
} as const;

export interface InvitationRoleOption {
  id: string;
  name: string;
}

/** What a successful `sendInvite` yields: enough to show and share the accept link. */
export interface SentInvitation {
  id: string;
  email: string;
  token: string;
}
