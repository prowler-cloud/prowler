"use client";

import { zodResolver } from "@hookform/resolvers/zod";
import { Link } from "@nextui-org/react";
import { useRouter } from "next/navigation";
import { useForm } from "react-hook-form";
import { z } from "zod";

import { authenticate, createNewUser } from "@/actions/auth";
import { NotificationIcon, ProwlerExtended } from "@/components/icons";
import { ThemeSwitch } from "@/components/ThemeSwitch";
import { useToast } from "@/components/ui";
import { CustomButton, CustomInput } from "@/components/ui/custom";
import { Form } from "@/components/ui/form";
import { ApiError, authFormSchema } from "@/types";

export const AuthForm = ({
  type,
  invitationToken,
  isCloudEnv,
}: {
  type: string;
  invitationToken?: string | null;
  isCloudEnv?: boolean;
}) => {
  const formSchema = authFormSchema(type);
  const router = useRouter();

  const form = useForm<z.infer<typeof formSchema>>({
    resolver: zodResolver(formSchema),
    defaultValues: {
      email: "",
      password: "",
      ...(type === "sign-up" && {
        name: "",
        company: "",
        confirmPassword: "",
        ...(invitationToken && { invitationToken }),
      }),
    },
  });

  const isLoading = form.formState.isSubmitting;
  const { toast } = useToast();

  const onSubmit = async (data: z.infer<typeof formSchema>) => {
    if (type === "sign-in") {
      const result = await authenticate(null, {
        email: data.email.toLowerCase(),
        password: data.password,
      });
      if (result?.message === "Success") {
        router.push("/");
      } else if (result?.errors && "credentials" in result.errors) {
        form.setError("email", {
          type: "server",
          message: result.errors.credentials ?? "Incorrect email or password",
        });
      } else if (result?.message === "User email is not verified") {
        router.push("/email-verification");
      } else {
        toast({
          variant: "destructive",
          title: "Oops! Something went wrong",
          description: "An unexpected error occurred. Please try again.",
        });
      }
    }

    if (type === "sign-up") {
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
          switch (error.source.pointer) {
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
    }
  };

  return (
    <div className="relative flex h-screen w-screen">
      {/* Auth Form */}
      <div className="relative flex w-full items-center justify-center lg:w-full">
        {/* Background Pattern */}
        <div className="absolute h-full w-full bg-[radial-gradient(#6af400_1px,transparent_1px)] [background-size:16px_16px] [mask-image:radial-gradient(ellipse_50%_50%_at_50%_50%,#000_10%,transparent_80%)]"></div>

        <div className="relative z-10 flex w-full max-w-sm flex-col gap-4 rounded-large border-1 border-divider bg-white/90 px-8 py-10 shadow-small dark:bg-background/85 md:max-w-md">
          {/* Prowler Logo */}
          <div className="absolute -top-[100px] left-1/2 z-10 flex h-fit w-fit -translate-x-1/2">
            <ProwlerExtended width={300} />
          </div>
          <div className="flex items-center justify-between">
            <p className="pb-2 text-xl font-medium">
              {type === "sign-in" ? "Sign In" : "Sign Up"}
            </p>
            <ThemeSwitch aria-label="Toggle theme" />
          </div>

          <Form {...form}>
            <form
              className="flex flex-col gap-3"
              onSubmit={form.handleSubmit(onSubmit)}
            >
              {type === "sign-up" && (
                <>
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
                    label="Company Name"
                    placeholder="Enter your company name"
                    isRequired={false}
                    isInvalid={!!form.formState.errors.company}
                  />
                </>
              )}
              <CustomInput
                control={form.control}
                name="email"
                type="email"
                label="Email"
                placeholder="Enter your email"
                isInvalid={!!form.formState.errors.email}
              />

              <CustomInput
                control={form.control}
                name="password"
                password
                isInvalid={!!form.formState.errors.password}
              />

              {/* {type === "sign-in" && (
                <div className="flex items-center justify-between px-1 py-2">
                  <Checkbox name="remember" size="sm">
                    Remember me
                  </Checkbox>
                  <Link className="text-default-500" href="#">
                    Forgot password?
                  </Link>
                </div>
              )} */}
              {type === "sign-up" && (
                <>
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
                    />
                  )}
                </>
              )}

              {form.formState.errors?.email && (
                <div className="flex flex-row items-center gap-2 text-system-error">
                  <NotificationIcon size={16} />
                  <p className="text-s">No user found</p>
                </div>
              )}

              <CustomButton
                type="submit"
                ariaLabel={type === "sign-in" ? "Log In" : "Sign Up"}
                ariaDisabled={isLoading}
                className="w-full"
                variant="solid"
                color="action"
                size="md"
                radius="md"
                isLoading={isLoading}
                isDisabled={isLoading}
              >
                {isLoading ? (
                  <span>Loading</span>
                ) : (
                  <span>{type === "sign-in" ? "Log In" : "Sign Up"}</span>
                )}
              </CustomButton>
            </form>
          </Form>

          {/* {type === "sign-in" && (
            <>
              <div className="flex items-center gap-4 py-2">
                <Divider className="flex-1" />
                <p className="shrink-0 text-tiny text-default-500">OR</p>
                <Divider className="flex-1" />
              </div>
              <div className="flex flex-col gap-2">
                <Button
                  startContent={
                    <Icon icon="flat-color-icons:google" width={24} />
                  }
                  variant="bordered"
                >
                  Continue with Google
                </Button>
                <Button
                  startContent={
                    <Icon
                      className="text-default-500"
                      icon="fe:github"
                      width={24}
                    />
                  }
                  variant="bordered"
                >
                  Continue with Github
                </Button>
              </div>
            </>
          )} */}
          {type === "sign-in" ? (
            <p className="text-center text-small">
              Need to create an account?&nbsp;
              <Link href="/sign-up">Sign Up</Link>
            </p>
          ) : (
            <p className="text-center text-small">
              Already have an account?&nbsp;
              <Link href="/sign-in">Log In</Link>
            </p>
          )}
        </div>
      </div>
    </div>
  );
};
