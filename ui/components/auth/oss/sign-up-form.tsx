"use client";

import { Checkbox } from "@heroui/checkbox";
import { zodResolver } from "@hookform/resolvers/zod";
import { useRouter } from "next/navigation";
import { useForm, useWatch } from "react-hook-form";

import { createNewUser } from "@/actions/auth";
import { AuthDivider } from "@/components/auth/oss/auth-divider";
import { AuthFooterLink } from "@/components/auth/oss/auth-footer-link";
import { AuthLayout } from "@/components/auth/oss/auth-layout";
import { PasswordRequirementsMessage } from "@/components/auth/oss/password-validator";
import { SocialButtons } from "@/components/auth/oss/social-buttons";
import { Button } from "@/components/shadcn";
import { useToast } from "@/components/ui";
import { CustomInput } from "@/components/ui/custom";
import { CustomLink } from "@/components/ui/custom/custom-link";
import {
  Form,
  FormControl,
  FormField,
  FormMessage,
} from "@/components/ui/form";
import { ApiError, SignUpFormData, signUpSchema } from "@/types";

const AUTH_ERROR_PATHS = {
  NAME: "/data/attributes/name",
  EMAIL: "/data/attributes/email",
  PASSWORD: "/data/attributes/password",
  COMPANY_NAME: "/data/attributes/company_name",
  INVITATION_TOKEN: "/data",
} as const;

export const SignUpForm = ({
  invitationToken,
  googleAuthUrl,
  githubAuthUrl,
  isGoogleOAuthEnabled,
  isGithubOAuthEnabled,
}: {
  invitationToken?: string | null;
  googleAuthUrl?: string;
  githubAuthUrl?: string;
  isGoogleOAuthEnabled?: boolean;
  isGithubOAuthEnabled?: boolean;
}) => {
  const router = useRouter();
  const { toast } = useToast();

  const form = useForm<SignUpFormData>({
    resolver: zodResolver(signUpSchema),
    mode: "onSubmit",
    reValidateMode: "onSubmit",
    defaultValues: {
      email: "",
      password: "",
      isSamlMode: false,
      name: "",
      company: "",
      confirmPassword: "",
      ...(invitationToken && { invitationToken }),
    },
  });

  const passwordValue = useWatch({
    control: form.control,
    name: "password",
    defaultValue: "",
  });

  const isLoading = form.formState.isSubmitting;

  const onSubmit = async (data: SignUpFormData) => {
    const newUser = await createNewUser(data);

    if (!newUser.errors) {
      toast({
        title: "Success!",
        description: "The user was registered successfully.",
      });
      form.reset();

      if (process.env.NEXT_PUBLIC_IS_CLOUD_ENV === "true") {
        router.push("/email-verification");
      } else {
        router.push("/sign-in");
      }
    } else {
      newUser.errors.forEach((error: ApiError) => {
        const errorMessage = error.detail;
        const pointer = error.source?.pointer;
        switch (pointer) {
          case AUTH_ERROR_PATHS.NAME:
            form.setError("name", { type: "server", message: errorMessage });
            break;
          case AUTH_ERROR_PATHS.EMAIL:
            form.setError("email", { type: "server", message: errorMessage });
            break;
          case AUTH_ERROR_PATHS.COMPANY_NAME:
            form.setError("company", {
              type: "server",
              message: errorMessage,
            });
            break;
          case AUTH_ERROR_PATHS.PASSWORD:
            form.setError("password", {
              type: "server",
              message: errorMessage,
            });
            break;
          case AUTH_ERROR_PATHS.INVITATION_TOKEN:
            form.setError("invitationToken", {
              type: "server",
              message: errorMessage,
            });
            break;
          default:
            toast({
              variant: "destructive",
              title: "Oops! Something went wrong",
              description: errorMessage,
            });
        }
      });
    }
  };

  return (
    <AuthLayout title="Sign up">
      <Form {...form}>
        <form
          noValidate
          method="post"
          className="flex flex-col gap-4"
          onSubmit={form.handleSubmit(onSubmit)}
        >
          <CustomInput
            control={form.control}
            name="name"
            type="text"
            label="Name"
            placeholder="Enter your name"
          />
          <CustomInput
            control={form.control}
            name="company"
            type="text"
            label="Company name"
            placeholder="Enter your company name"
            isRequired={false}
          />
          <CustomInput
            control={form.control}
            name="email"
            type="email"
            label="Email"
            placeholder="Enter your email"
          />
          <CustomInput control={form.control} name="password" password />
          <PasswordRequirementsMessage password={passwordValue || ""} />
          <CustomInput
            control={form.control}
            name="confirmPassword"
            confirmPassword
          />
          {invitationToken && (
            <CustomInput
              control={form.control}
              name="invitationToken"
              type="text"
              label="Invitation Token"
              placeholder={invitationToken}
              defaultValue={invitationToken}
              isRequired={false}
              isDisabled={invitationToken !== null && true}
            />
          )}

          {process.env.NEXT_PUBLIC_IS_CLOUD_ENV === "true" && (
            <FormField
              control={form.control}
              name="termsAndConditions"
              render={({ field }) => (
                <>
                  <FormControl>
                    <Checkbox
                      isRequired
                      className="py-4"
                      size="sm"
                      checked={field.value}
                      onChange={(e) => field.onChange(e.target.checked)}
                      color="default"
                    >
                      I agree with the&nbsp;
                      <CustomLink
                        href="https://prowler.com/terms-of-service/"
                        size="sm"
                      >
                        Terms of Service
                      </CustomLink>
                      &nbsp;of Prowler
                    </Checkbox>
                  </FormControl>
                  <FormMessage className="text-text-error" />
                </>
              )}
            />
          )}

          <Button
            type="submit"
            aria-label="Sign up"
            aria-disabled={isLoading}
            className="w-full"
            disabled={isLoading}
          >
            {isLoading ? "Loading..." : "Sign up"}
          </Button>
        </form>
      </Form>

      {!invitationToken && (
        <>
          <AuthDivider />
          <div className="flex flex-col gap-2">
            <SocialButtons
              googleAuthUrl={googleAuthUrl}
              githubAuthUrl={githubAuthUrl}
              isGoogleOAuthEnabled={isGoogleOAuthEnabled}
              isGithubOAuthEnabled={isGithubOAuthEnabled}
            />
          </div>
        </>
      )}

      <AuthFooterLink
        text="Already have an account?"
        linkText="Log in"
        href="/sign-in"
      />
    </AuthLayout>
  );
};
