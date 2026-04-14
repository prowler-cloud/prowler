/**
 * Query param name + value used to bypass the backward-compat redirect
 * in proxy.ts when the user explicitly chose "Create an account"
 * from the invitation smart router.
 *
 * Client sends: /sign-up?invitation_token=…&action=signup
 * Proxy skips redirect when "action" param is present.
 */
export const INVITATION_ACTION_PARAM = "action";
export const INVITATION_SIGNUP_ACTION = "signup";
