"use client";

import { Icon } from "@iconify/react";
import Link from "next/link";
import { signOut } from "next-auth/react";
import { useRouter } from "next/navigation";
import { useEffect, useRef, useState } from "react";

import { acceptInvitation } from "@/actions/invitations";
import { Button } from "@/components/shadcn";
import {
  INVITATION_ACTION_PARAM,
  INVITATION_SIGNUP_ACTION,
} from "@/lib/invitation-routing";

type AcceptState =
  | { kind: "no-token" }
  | { kind: "accepting" }
  | { kind: "error"; message: string; canRetry: boolean; needsSignOut: boolean }
  | { kind: "choose" };

function mapApiError(status: number | undefined): {
  message: string;
  canRetry: boolean;
  needsSignOut: boolean;
} {
  switch (status) {
    case 410:
      return {
        message:
          "This invitation has expired. Please contact your administrator for a new one.",
        canRetry: false,
        needsSignOut: false,
      };
    case 400:
      return {
        message: "This invitation has already been used.",
        canRetry: false,
        needsSignOut: false,
      };
    case 404:
      return {
        message:
          "This invitation was sent to a different email address. Please sign in with the correct account.",
        canRetry: false,
        needsSignOut: true,
      };
    default:
      return {
        message: "Something went wrong while accepting the invitation.",
        canRetry: true,
        needsSignOut: false,
      };
  }
}

export function AcceptInvitationClient({
  isAuthenticated,
  token,
}: {
  isAuthenticated: boolean;
  token: string | null;
}) {
  const router = useRouter();
  const [state, setState] = useState<AcceptState>(() => {
    if (!token) return { kind: "no-token" };
    if (!isAuthenticated) return { kind: "choose" };
    return { kind: "accepting" };
  });
  const hasStartedRef = useRef(false);

  async function doAccept() {
    if (!token) return;
    setState({ kind: "accepting" });

    const result = await acceptInvitation(token);

    if (result?.error) {
      const { message, canRetry, needsSignOut } = mapApiError(result.status);
      setState({ kind: "error", message, canRetry, needsSignOut });
    } else {
      router.push("/");
    }
  }

  async function handleSignOutAndRedirect() {
    if (!token) return;
    const callbackPath = `/invitation/accept?invitation_token=${encodeURIComponent(token)}`;
    await signOut({ redirect: false });
    router.push(`/sign-in?callbackUrl=${encodeURIComponent(callbackPath)}`);
  }

  useEffect(() => {
    if (hasStartedRef.current) return;
    hasStartedRef.current = true;

    if (!token) {
      setState({ kind: "no-token" });
      return;
    }

    if (isAuthenticated) {
      doAccept();
    } else {
      setState({ kind: "choose" });
    }
  }, [token, isAuthenticated]); // eslint-disable-line react-hooks/exhaustive-deps

  return (
    <div className="flex min-h-screen items-center justify-center p-4">
      <div className="w-full max-w-md space-y-6 text-center">
        {/* No token */}
        {state.kind === "no-token" && (
          <div className="flex flex-col items-center gap-4">
            <Icon
              icon="solar:danger-triangle-bold"
              className="text-warning"
              width={48}
            />
            <h1 className="text-xl font-semibold">Invalid Invitation Link</h1>
            <p className="text-default-500">
              No invitation token was provided. Please check the link you
              received.
            </p>
            <Button asChild variant="outline">
              <Link href="/sign-in">Go to Sign In</Link>
            </Button>
          </div>
        )}

        {/* Accepting */}
        {state.kind === "accepting" && (
          <div className="flex flex-col items-center gap-4">
            <Icon
              icon="eos-icons:loading"
              className="text-default-500"
              width={48}
            />
            <h1 className="text-xl font-semibold">Accepting Invitation...</h1>
            <p className="text-default-500">
              Please wait while we process your invitation.
            </p>
          </div>
        )}

        {/* Error */}
        {state.kind === "error" && (
          <div className="flex flex-col items-center gap-4">
            <Icon
              icon="solar:danger-triangle-bold"
              className="text-danger"
              width={48}
            />
            <h1 className="text-xl font-semibold">
              Could Not Accept Invitation
            </h1>
            <p className="text-default-500">{state.message}</p>
            <div className="flex gap-3">
              {state.canRetry && <Button onClick={doAccept}>Retry</Button>}
              {state.needsSignOut ? (
                <Button variant="outline" onClick={handleSignOutAndRedirect}>
                  Sign in with a different account
                </Button>
              ) : (
                <Button asChild variant="outline">
                  <Link href="/sign-in">Go to Sign In</Link>
                </Button>
              )}
            </div>
          </div>
        )}

        {/* Choice page for unauthenticated users */}
        {state.kind === "choose" && (
          <div className="flex flex-col items-center gap-6">
            <Icon
              icon="solar:letter-bold"
              className="text-primary"
              width={48}
            />
            <div>
              <h1 className="text-xl font-semibold">
                You&apos;ve Been Invited
              </h1>
              <p className="text-default-500 mt-2">
                You&apos;ve been invited to join a tenant on Prowler. How would
                you like to continue?
              </p>
            </div>
            <div className="flex w-full flex-col gap-3">
              <Button
                className="w-full"
                onClick={() => {
                  const callbackPath = `/invitation/accept?invitation_token=${encodeURIComponent(token!)}`;
                  router.push(
                    `/sign-in?callbackUrl=${encodeURIComponent(callbackPath)}`,
                  );
                }}
              >
                I have an account — Sign in
              </Button>
              <Button
                variant="outline"
                className="w-full"
                onClick={() => {
                  router.push(
                    `/sign-up?invitation_token=${encodeURIComponent(token!)}&${INVITATION_ACTION_PARAM}=${INVITATION_SIGNUP_ACTION}`,
                  );
                }}
              >
                I&apos;m new — Create an account
              </Button>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
