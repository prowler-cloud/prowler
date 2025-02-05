import { AuthForm } from "@/components/auth/oss";
import { SearchParamsProps } from "@/types";

const SignUp = ({ searchParams }: { searchParams: SearchParamsProps }) => {
  const invitationToken =
    typeof searchParams?.invitation_token === "string"
      ? searchParams.invitation_token
      : null;

  return <AuthForm type="sign-up" invitationToken={invitationToken} />;
};

export default SignUp;
