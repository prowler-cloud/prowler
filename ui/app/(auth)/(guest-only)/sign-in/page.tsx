import { AuthForm } from "@/components/auth/oss";
import {
  getAuthUrl,
  isGithubOAuthEnabled,
  isGoogleOAuthEnabled,
  isMicrosoftOAuthEnabled,
} from "@/lib/helper";
import { isSelfRegistrationEnabled } from "@/lib/shared/env";

const SignIn = () => {
  const GOOGLE_AUTH_URL = getAuthUrl("google");
  const GITHUB_AUTH_URL = getAuthUrl("github");
  const MICROSOFT_AUTH_URL = getAuthUrl("microsoft");
  return (
    <AuthForm
      type="sign-in"
      googleAuthUrl={GOOGLE_AUTH_URL}
      githubAuthUrl={GITHUB_AUTH_URL}
      microsoftAuthUrl={MICROSOFT_AUTH_URL}
      isGoogleOAuthEnabled={isGoogleOAuthEnabled}
      isGithubOAuthEnabled={isGithubOAuthEnabled}
      isMicrosoftOAuthEnabled={isMicrosoftOAuthEnabled}
      isSelfRegistrationEnabled={isSelfRegistrationEnabled()}
    />
  );
};

export default SignIn;
