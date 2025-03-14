import { AuthForm } from "@/components/auth/oss";
import { isGithubOAuthEnabled, isGoogleOAuthEnabled } from "@/lib/helper";

const SignIn = () => {
  return (
    <AuthForm
      type="sign-in"
      isGoogleOAuthEnabled={isGoogleOAuthEnabled}
      isGithubOAuthEnabled={isGithubOAuthEnabled}
    />
  );
};

export default SignIn;
