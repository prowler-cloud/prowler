import { redirect } from "next/navigation";

import { AuthForm } from "@/components/auth/oss";
import {
  getAuthUrl,
  isGithubOAuthEnabled,
  isGoogleOAuthEnabled,
  isMicrosoftOAuthEnabled,
} from "@/lib/helper";
import { isCloud, isSelfRegistrationEnabled } from "@/lib/shared/env";
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
  if (!invitationToken && !isSelfRegistrationEnabled()) {
    redirect("/sign-in");
  }
  const isCloudEnv = isCloud();

  const GOOGLE_AUTH_URL = getAuthUrl("google");
  const GITHUB_AUTH_URL = getAuthUrl("github");
  const MICROSOFT_AUTH_URL = getAuthUrl("microsoft");

  return (
    <AuthForm
      type="sign-up"
      invitationToken={invitationToken}
      isCloudEnv={isCloudEnv}
      googleAuthUrl={GOOGLE_AUTH_URL}
      githubAuthUrl={GITHUB_AUTH_URL}
      microsoftAuthUrl={MICROSOFT_AUTH_URL}
      isGoogleOAuthEnabled={isGoogleOAuthEnabled}
      isGithubOAuthEnabled={isGithubOAuthEnabled}
      isMicrosoftOAuthEnabled={isMicrosoftOAuthEnabled}
    />
  );
};

export default SignUp;
