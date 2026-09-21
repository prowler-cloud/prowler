// Query param the API can read to tell where an invitation was sent from.
export const INVITATION_SOURCE_PARAM = "source";

export const INVITATION_SOURCE = {
  ONBOARDING: "onboarding",
} as const;

export interface InvitationRoleOption {
  id: string;
  name: string;
}
