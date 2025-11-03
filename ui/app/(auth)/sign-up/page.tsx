import { redirect } from "next/navigation";

import { AuthForm } from "@/components/auth/oss";
import { getAuthUrl, isGithubOAuthEnabled } from "@/lib/helper";
import { isGoogleOAuthEnabled } from "@/lib/helper";
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

  // Allow sign-up only if tenant creation is enabled OR user has an invitation token
  const allowTenantCreation =
    process.env.NEXT_PUBLIC_ALLOW_TENANT_CREATION !== "false";
  if (!allowTenantCreation && !invitationToken) {
    redirect("/sign-in");
  }

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
    />
  );
};

export default SignUp;
