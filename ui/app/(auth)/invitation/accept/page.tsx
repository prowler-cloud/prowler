import { Suspense } from "react";

import { auth } from "@/auth.config";
import { SearchParamsProps } from "@/types";

import { AcceptInvitationClient } from "./accept-invitation-client";

export default async function AcceptInvitationPage({
  searchParams,
}: {
  searchParams: Promise<SearchParamsProps>;
}) {
  const session = await auth();
  const resolvedSearchParams = await searchParams;

  const token =
    typeof resolvedSearchParams?.invitation_token === "string"
      ? resolvedSearchParams.invitation_token
      : null;

  return (
    <Suspense>
      <AcceptInvitationClient isAuthenticated={!!session?.user} token={token} />
    </Suspense>
  );
}
