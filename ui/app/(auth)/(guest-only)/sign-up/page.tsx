import { Suspense } from "react";

import { AuthForm } from "@/components/auth/oss";
import { AuthReleaseHighlightsServer } from "@/components/auth/oss/auth-release-highlights-server";
import { AuthReleaseHighlightsSkeleton } from "@/components/auth/oss/auth-release-highlights-skeleton";
import {
  getAuthUrl,
  isGithubOAuthEnabled,
  isGoogleOAuthEnabled,
} from "@/lib/helper";
import { SearchParamsProps } from "@/types";

const SignUp = async ({
  searchParams,
}: {
  searchParams: Promise<SearchParamsProps>;
}) => {
  const resolvedSearchParams = await searchParams;
  const invitationToken =
    typeof resolvedSearchParams?.invitation_token === "string"
      ? resolvedSearchParams.invitation_token
      : null;

  const GOOGLE_AUTH_URL = getAuthUrl("google");
  const GITHUB_AUTH_URL = getAuthUrl("github");

  return (
    <AuthForm
      type="sign-up"
      invitationToken={invitationToken}
      googleAuthUrl={GOOGLE_AUTH_URL}
      githubAuthUrl={GITHUB_AUTH_URL}
      isGoogleOAuthEnabled={isGoogleOAuthEnabled}
      isGithubOAuthEnabled={isGithubOAuthEnabled}
      releaseHighlights={
        <Suspense
          key="auth-release-highlights"
          fallback={<AuthReleaseHighlightsSkeleton />}
        >
          <AuthReleaseHighlightsServer />
        </Suspense>
      }
    />
  );
};

export default SignUp;
