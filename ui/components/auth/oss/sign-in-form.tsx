"use client";

import { zodResolver } from "@hookform/resolvers/zod";
import { Icon } from "@iconify/react";
import { useRouter, useSearchParams } from "next/navigation";
import { useEffect } from "react";
import { useForm } from "react-hook-form";

import { authenticate } from "@/actions/auth";
import { initiateSamlAuth } from "@/actions/integrations/saml";
import { AuthDivider } from "@/components/auth/oss/auth-divider";
import { AuthFooterLink } from "@/components/auth/oss/auth-footer-link";
import { AuthLayout } from "@/components/auth/oss/auth-layout";
import { SocialButtons } from "@/components/auth/oss/social-buttons";
import {
  Button,
  Tooltip,
  TooltipContent,
  TooltipTrigger,
  useToast,
} from "@/components/shadcn";
import { CustomInput } from "@/components/shadcn/custom";
import { Form } from "@/components/shadcn/form";
import { getSafeCallbackPath } from "@/lib/auth-callback-url";
import { stripPasswordManagerHighlight } from "@/lib/password-manager";
import { SignInFormData, signInSchema } from "@/types";

export const SignInForm = ({
  googleAuthUrl,
  githubAuthUrl,
  isGoogleOAuthEnabled,
  isGithubOAuthEnabled,
}: {
  googleAuthUrl?: string;
  githubAuthUrl?: string;
  isGoogleOAuthEnabled?: boolean;
  isGithubOAuthEnabled?: boolean;
}) => {
  const router = useRouter();
  const searchParams = useSearchParams();
  const { toast } = useToast();
  const callbackUrl = getSafeCallbackPath(searchParams, "callbackUrl");

  useEffect(() => {
    const samlError = searchParams.get("sso_saml_failed");
    const sessionError = searchParams.get("error");

    if (samlError) {
      setTimeout(() => {
        toast({
          variant: "destructive",
          title: "SAML Authentication Error",
          description:
            "An error occurred while attempting to login via your Identity Provider (IdP). Please check your IdP configuration.",
        });
      }, 100);
    }

    if (sessionError) {
      setTimeout(() => {
        const errorMessages: Record<
          string,
          { title: string; description: string }
        > = {
          RefreshAccessTokenError: {
            title: "Session Expired",
            description:
              "Your session has expired. Please sign in again to continue.",
          },
          MissingRefreshToken: {
            title: "Session Error",
            description:
              "There was a problem with your session. Please sign in again.",
          },
        };

        const errorConfig = errorMessages[sessionError] || {
          title: "Authentication Error",
          description: "Please sign in again to continue.",
        };

        toast({
          variant: "destructive",
          title: errorConfig.title,
          description: errorConfig.description,
        });
      }, 100);
    }
  }, [searchParams, toast]);

  const form = useForm<SignInFormData>({
    resolver: zodResolver(signInSchema),
    mode: "onSubmit",
    reValidateMode: "onSubmit",
    defaultValues: {
      email: "",
      password: "",
      isSamlMode: false,
    },
  });

  const isLoading = form.formState.isSubmitting;
  const isSamlMode = form.watch("isSamlMode");

  const onSubmit = async (data: SignInFormData) => {
    if (data.isSamlMode) {
      const email = data.email.toLowerCase();
      if (isSamlMode) {
        form.setValue("password", "");
      }

      const result = await initiateSamlAuth(email, callbackUrl);

      if (result.success && result.redirectUrl) {
        window.location.href = result.redirectUrl;
      } else {
        toast({
          variant: "destructive",
          title: "SAML Authentication Error",
          description:
            result.error || "An error occurred during SAML authentication.",
        });
      }
      return;
    }

    const result = await authenticate(null, {
      email: data.email.toLowerCase(),
      password: data.password,
    });

    if (result?.message === "Success") {
      router.push(callbackUrl);
    } else if (result?.errors && "credentials" in result.errors) {
      const message = result.errors.credentials ?? "Invalid email or password";

      form.setError("email", { type: "server", message });
      form.setError("password", { type: "server", message });
    } else if (result?.message === "User email is not verified") {
      router.push("/email-verification");
    } else {
      toast({
        variant: "destructive",
        title: "Oops! Something went wrong",
        description: "An unexpected error occurred. Please try again.",
      });
    }
  };

  const title = isSamlMode ? "Sign in with SAML SSO" : "Welcome back";

  return (
    <AuthLayout
      title={title}
      footer={
        <AuthFooterLink
          text="Need to create an account?"
          linkText="Sign up"
          href="/sign-up"
        />
      }
    >
      <Form {...form}>
        <form
          ref={stripPasswordManagerHighlight}
          noValidate
          method="post"
          className="flex flex-col gap-4"
          onSubmit={form.handleSubmit(onSubmit)}
        >
          <CustomInput
            control={form.control}
            name="email"
            type="email"
            label="Email"
            placeholder="Enter your email"
          />
          {!isSamlMode && (
            <CustomInput control={form.control} name="password" password />
          )}

          <Button
            type="submit"
            aria-label="Log in"
            aria-disabled={isLoading}
            className="w-full"
            disabled={isLoading}
          >
            {isLoading ? "Loading..." : "Log in"}
          </Button>
        </form>
      </Form>

      <AuthDivider />

      <div className="flex gap-2">
        {!isSamlMode && (
          <SocialButtons
            googleAuthUrl={googleAuthUrl}
            githubAuthUrl={githubAuthUrl}
            callbackUrl={callbackUrl}
            isGoogleOAuthEnabled={isGoogleOAuthEnabled}
            isGithubOAuthEnabled={isGithubOAuthEnabled}
          />
        )}
        {isSamlMode ? (
          <Button
            variant="outline"
            className="flex-1"
            onClick={() => {
              form.setValue("isSamlMode", false);
            }}
          >
            Back
          </Button>
        ) : (
          <Tooltip>
            <TooltipTrigger asChild>
              <Button
                variant="outline"
                aria-label="Continue with SAML SSO"
                className="flex-1"
                onClick={() => {
                  form.setValue("isSamlMode", true);
                }}
              >
                <Icon
                  className="text-text-neutral-tertiary"
                  icon="mdi:shield-key"
                  width={24}
                />
              </Button>
            </TooltipTrigger>
            <TooltipContent side="top">Continue with SAML SSO</TooltipContent>
          </Tooltip>
        )}
      </div>
    </AuthLayout>
  );
};
