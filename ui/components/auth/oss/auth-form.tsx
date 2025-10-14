import { SignInForm } from "@/components/auth/oss/sign-in-form";
import { SignUpForm } from "@/components/auth/oss/sign-up-form";

export const AuthForm = ({
  type,
  invitationToken,
  googleAuthUrl,
  githubAuthUrl,
  isGoogleOAuthEnabled,
  isGithubOAuthEnabled,
}: {
  type: string;
  invitationToken?: string | null;
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
      googleAuthUrl={googleAuthUrl}
      githubAuthUrl={githubAuthUrl}
      isGoogleOAuthEnabled={isGoogleOAuthEnabled}
      isGithubOAuthEnabled={isGithubOAuthEnabled}
    />
  );
};
