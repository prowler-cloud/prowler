import { SignInForm } from "@/components/auth/oss/sign-in-form";
import { SignUpForm } from "@/components/auth/oss/sign-up-form";

export const AuthForm = ({
  type,
  invitationToken,
  isCloudEnv,
  googleAuthUrl,
  githubAuthUrl,
  isGoogleOAuthEnabled,
  isGithubOAuthEnabled,
}: {
  type: string;
  invitationToken?: string | null;
  isCloudEnv?: boolean;
  googleAuthUrl?: string;
  githubAuthUrl?: string;
  isGoogleOAuthEnabled?: boolean;
  isGithubOAuthEnabled?: boolean;
}) => {
  if (type === "sign-in") {
    return (
      <SignInForm
        googleAuthUrl={googleAuthUrl}
        githubAuthUrl={githubAuthUrl}
        isGoogleOAuthEnabled={isGoogleOAuthEnabled}
        isGithubOAuthEnabled={isGithubOAuthEnabled}
      />
    );
  }

  return (
    <SignUpForm
      invitationToken={invitationToken}
      isCloudEnv={isCloudEnv}
      googleAuthUrl={googleAuthUrl}
      githubAuthUrl={githubAuthUrl}
      isGoogleOAuthEnabled={isGoogleOAuthEnabled}
      isGithubOAuthEnabled={isGithubOAuthEnabled}
    />
  );
};
