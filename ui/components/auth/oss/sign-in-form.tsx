"use client";

import { Button } from "@heroui/button";
import { Divider } from "@heroui/divider";
import { zodResolver } from "@hookform/resolvers/zod";
import { Icon } from "@iconify/react";
import { useRouter, useSearchParams } from "next/navigation";
import { useEffect } from "react";
import { useForm } from "react-hook-form";

import { authenticate } from "@/actions/auth";
import { initiateSamlAuth } from "@/actions/integrations/saml";
import { SocialButtons } from "@/components/auth/oss/social-buttons";
import { ProwlerExtended } from "@/components/icons";
import { ThemeSwitch } from "@/components/ThemeSwitch";
import { useToast } from "@/components/ui";
import { CustomButton, CustomInput } from "@/components/ui/custom";
import { CustomLink } from "@/components/ui/custom/custom-link";
import { Form } from "@/components/ui/form";
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

  useEffect(() => {
    const samlError = searchParams.get("sso_saml_failed");

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

      const result = await initiateSamlAuth(email);

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
      router.push("/");
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

  return (
    <div className="relative flex h-screen w-screen">
      <div className="relative flex w-full items-center justify-center lg:w-full">
        <div className="absolute h-full w-full bg-[radial-gradient(#6af400_1px,transparent_1px)] mask-[radial-gradient(ellipse_50%_50%_at_50%_50%,#000_10%,transparent_80%)] bg-size-[16px_16px]"></div>

        <div className="rounded-large border-divider shadow-small dark:bg-background/85 relative z-10 flex w-full max-w-sm flex-col gap-4 border bg-white/90 px-8 py-10 md:max-w-md">
          <div className="absolute -top-[100px] left-1/2 z-10 flex h-fit w-fit -translate-x-1/2">
            <ProwlerExtended width={300} />
          </div>
          <div className="flex items-center justify-between">
            <p className="pb-2 text-xl font-medium">
              {isSamlMode ? "Sign in with SAML SSO" : "Sign in"}
            </p>
            <ThemeSwitch aria-label="Toggle theme" />
          </div>

          <Form {...form}>
            <form
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
                isInvalid={!!form.formState.errors.email}
                showFormMessage
              />
              {!isSamlMode && (
                <CustomInput
                  control={form.control}
                  name="password"
                  password
                  isInvalid={!!form.formState.errors.password}
                />
              )}

              <CustomButton
                type="submit"
                ariaLabel="Log in"
                ariaDisabled={isLoading}
                className="w-full"
                variant="solid"
                color="action"
                size="md"
                radius="md"
                isLoading={isLoading}
                isDisabled={isLoading}
              >
                {isLoading ? <span>Loading</span> : <span>Log in</span>}
              </CustomButton>
            </form>
          </Form>

          <>
            <div className="flex items-center gap-4 py-2">
              <Divider className="flex-1" />
              <p className="text-tiny text-default-500 shrink-0">OR</p>
              <Divider className="flex-1" />
            </div>
            <div className="flex flex-col gap-2">
              {!isSamlMode && (
                <SocialButtons
                  googleAuthUrl={googleAuthUrl}
                  githubAuthUrl={githubAuthUrl}
                  isGoogleOAuthEnabled={isGoogleOAuthEnabled}
                  isGithubOAuthEnabled={isGithubOAuthEnabled}
                />
              )}
              <Button
                startContent={
                  !isSamlMode && (
                    <Icon
                      className="text-default-500"
                      icon="mdi:shield-key"
                      width={24}
                    />
                  )
                }
                variant="bordered"
                className="w-full"
                onClick={() => {
                  form.setValue("isSamlMode", !isSamlMode);
                }}
              >
                {isSamlMode ? "Back" : "Continue with SAML SSO"}
              </Button>
            </div>
          </>

          <p className="text-small text-center">
            Need to create an account?&nbsp;
            <CustomLink size="base" href="/sign-up" target="_self">
              Sign up
            </CustomLink>
          </p>
        </div>
      </div>
    </div>
  );
};
