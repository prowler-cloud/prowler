const INVITATION_ACCEPT_PATH = "/invitation/accept";

/** Link an invitee opens to join the tenant; the API only hands back the token. */
export function buildInvitationAcceptLink(
  token: string,
  origin: string,
): string {
  return `${origin}${INVITATION_ACCEPT_PATH}?invitation_token=${encodeURIComponent(token)}`;
}
