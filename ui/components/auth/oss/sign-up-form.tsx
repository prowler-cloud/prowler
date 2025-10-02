"use client";

import { Checkbox } from "@heroui/checkbox";
import { Divider } from "@heroui/divider";
import { zodResolver } from "@hookform/resolvers/zod";
import { useRouter } from "next/navigation";
import { useForm } from "react-hook-form";

import { createNewUser } from "@/actions/auth";
import { PasswordRequirementsMessage } from "@/components/auth/oss/password-validator";
import { SocialButtons } from "@/components/auth/oss/social-buttons";
import { ProwlerExtended } from "@/components/icons";
import { ThemeSwitch } from "@/components/ThemeSwitch";
import { useToast } from "@/components/ui";
import { CustomButton, CustomInput } from "@/components/ui/custom";
import { CustomLink } from "@/components/ui/custom/custom-link";
import {
  Form,
  FormControl,
  FormField,
  FormMessage,
} from "@/components/ui/form";
import { ApiError, SignUpFormData, signUpSchema } from "@/types";

export const SignUpForm = ({
  invitationToken,
  isCloudEnv,
  googleAuthUrl,
  githubAuthUrl,
  isGoogleOAuthEnabled,
  isGithubOAuthEnabled,
}: {
  invitationToken?: string | null;
  isCloudEnv?: boolean;
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

  const isLoading = form.formState.isSubmitting;

  const onSubmit = async (data: SignUpFormData) => {
    const newUser = await createNewUser(data);

    if (!newUser.errors) {
      toast({
        title: "Success!",
        description: "The user was registered successfully.",
      });
      form.reset();

      if (isCloudEnv) {
        router.push("/email-verification");
      } else {
        router.push("/sign-in");
      }
    } else {
      newUser.errors.forEach((error: ApiError) => {
        const errorMessage = error.detail;
        const pointer = error.source?.pointer;
        switch (pointer) {
          case "/data/attributes/name":
            form.setError("name", { type: "server", message: errorMessage });
            break;
          case "/data/attributes/email":
            form.setError("email", { type: "server", message: errorMessage });
            break;
          case "/data/attributes/company_name":
            form.setError("company", {
              type: "server",
              message: errorMessage,
            });
            break;
          case "/data/attributes/password":
            form.setError("password", {
              type: "server",
              message: errorMessage,
            });
            break;
          case "/data":
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
    <div className="relative flex h-screen w-screen">
      <div className="relative flex w-full items-center justify-center lg:w-full">
        <div className="absolute h-full w-full bg-[radial-gradient(#6af400_1px,transparent_1px)] mask-[radial-gradient(ellipse_50%_50%_at_50%_50%,#000_10%,transparent_80%)] bg-size-[16px_16px]"></div>

        <div className="rounded-large border-divider shadow-small dark:bg-background/85 relative z-10 flex w-full max-w-sm flex-col gap-4 border bg-white/90 px-8 py-10 md:max-w-md">
          <div className="absolute -top-[100px] left-1/2 z-10 flex h-fit w-fit -translate-x-1/2">
            <ProwlerExtended width={300} />
          </div>
          <div className="flex items-center justify-between">
            <p className="pb-2 text-xl font-medium">Sign up</p>
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
                name="name"
                type="text"
                label="Name"
                placeholder="Enter your name"
                isInvalid={!!form.formState.errors.name}
              />
              <CustomInput
                control={form.control}
                name="company"
                type="text"
                label="Company name"
                placeholder="Enter your company name"
                isRequired={false}
                isInvalid={!!form.formState.errors.company}
              />
              <CustomInput
                control={form.control}
                name="email"
                type="email"
                label="Email"
                placeholder="Enter your email"
                isInvalid={!!form.formState.errors.email}
                showFormMessage
              />
              <CustomInput
                control={form.control}
                name="password"
                password
                isInvalid={!!form.formState.errors.password}
              />
              <PasswordRequirementsMessage
                password={form.watch("password") || ""}
              />
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
                  isInvalid={!!form.formState.errors.invitationToken}
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
                      <FormMessage className="text-system-error dark:text-system-error" />
                    </>
                  )}
                />
              )}

              <CustomButton
                type="submit"
                ariaLabel="Sign up"
                ariaDisabled={isLoading}
                className="w-full"
                variant="solid"
                color="action"
                size="md"
                radius="md"
                isLoading={isLoading}
                isDisabled={isLoading}
              >
                {isLoading ? <span>Loading</span> : <span>Sign up</span>}
              </CustomButton>
            </form>
          </Form>

          {!invitationToken && (
            <>
              <div className="flex items-center gap-4 py-2">
                <Divider className="flex-1" />
                <p className="text-tiny text-default-500 shrink-0">OR</p>
                <Divider className="flex-1" />
              </div>
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

          <p className="text-small text-center">
            Already have an account?&nbsp;
            <CustomLink size="base" href="/sign-in" target="_self">
              Log in
            </CustomLink>
          </p>
        </div>
      </div>
    </div>
  );
};
