import { SignInForm } from "@/components/auth/oss/sign-in-form";
import { SignUpForm } from "@/components/auth/oss/sign-up-form";

export const AuthForm = ({
  type,
  invitationToken,
  isCloudEnv,
  googleAuthUrl,
  githubAuthUrl,
  microsoftAuthUrl,
  isGoogleOAuthEnabled,
  isGithubOAuthEnabled,
  isMicrosoftOAuthEnabled,
  isSelfRegistrationEnabled = true,
}: {
  type: string;
  invitationToken?: string | null;
  isCloudEnv?: boolean;
  googleAuthUrl?: string;
  githubAuthUrl?: string;
  microsoftAuthUrl?: string;
  isGoogleOAuthEnabled?: boolean;
  isGithubOAuthEnabled?: boolean;
  isMicrosoftOAuthEnabled?: boolean;
  isSelfRegistrationEnabled?: boolean;
}) => {
  if (type === "sign-in") {
    return (
      <SignInForm
        googleAuthUrl={googleAuthUrl}
        githubAuthUrl={githubAuthUrl}
        microsoftAuthUrl={microsoftAuthUrl}
        isGoogleOAuthEnabled={isGoogleOAuthEnabled}
        isGithubOAuthEnabled={isGithubOAuthEnabled}
        isMicrosoftOAuthEnabled={isMicrosoftOAuthEnabled}
        isSelfRegistrationEnabled={isSelfRegistrationEnabled}
      />
    );
  }

  return (
    <SignUpForm
      invitationToken={invitationToken}
      isCloudEnv={isCloudEnv}
      googleAuthUrl={googleAuthUrl}
      githubAuthUrl={githubAuthUrl}
      microsoftAuthUrl={microsoftAuthUrl}
      isGoogleOAuthEnabled={isGoogleOAuthEnabled}
      isGithubOAuthEnabled={isGithubOAuthEnabled}
      isMicrosoftOAuthEnabled={isMicrosoftOAuthEnabled}
    />
  );
};
