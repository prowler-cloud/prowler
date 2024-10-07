"use client";

import { zodResolver } from "@hookform/resolvers/zod";
import { Icon } from "@iconify/react";
import { Button, Checkbox, Divider, Link } from "@nextui-org/react";
import { useRouter } from "next/navigation";
import { useEffect } from "react";
import { useFormState } from "react-dom";
import { useForm } from "react-hook-form";
import { z } from "zod";

import { authenticate, createNewUser } from "@/actions/auth";
import {
  Form,
  FormControl,
  FormField,
  FormMessage,
} from "@/components/ui/form";
import { ApiError, authFormSchema } from "@/types";

import { NotificationIcon, ProwlerExtended } from "../icons";
import { ThemeSwitch } from "../ThemeSwitch";
import { CustomButton, CustomInput } from "../ui/custom";
import { useToast } from "../ui/toast";

export const AuthForm = ({ type }: { type: string }) => {
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
        termsAndConditions: false,
        confirmPassword: "",
      }),
    },
  });

  const [state, dispatch] = useFormState(authenticate, undefined);

  const { toast } = useToast();

  const isLoading = form.formState.isSubmitting;

  useEffect(() => {
    if (state?.message === "Success") {
      router.push("/");
    }
  }, [state]);

  const onSubmit = async (data: z.infer<typeof formSchema>) => {
    if (type === "sign-in") {
      dispatch({
        email: data.email.toLowerCase(),
        password: data.password,
      });
    }
    if (type === "sign-up") {
      const newUser = await createNewUser(data);

      if (!newUser.errors) {
        router.push("/sign-in");
      }

      if (newUser?.errors && newUser.errors.length > 0) {
        newUser.errors.forEach((error: ApiError) => {
          const errorMessage = error.detail;

          switch (error.source.pointer) {
            case "/data/attributes/name":
              form.setError("name", { type: "server", message: errorMessage });
              break;
            case "/data/attributes/email":
              form.setError("email", { type: "server", message: errorMessage });
              break;
            case "/data/attributes/password":
              form.setError("password", {
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
      } else {
        toast({
          title: "Success!",
          description: "The user was registered successfully.",
        });
        form.reset({
          name: "",
          company: "",
          email: "",
          password: "",
          termsAndConditions: false,
        });
      }
    }
  };

  return (
    <div className="relative flex h-screen w-screen">
      {/* Auth Form */}
      <div className="relative flex w-full items-center justify-center bg-background lg:w-1/2">
        {/* Prowler Logo */}
        <div className="absolute top-[10%] z-10 flex h-fit w-fit flex-col items-center lg:hidden">
          <ProwlerExtended width={300} />
        </div>

        <div className="flex w-full max-w-sm flex-col gap-4 rounded-large bg-content1 px-8 pb-10 pt-6 shadow-small">
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

              {type === "sign-in" && (
                <div className="flex items-center justify-between px-1 py-2">
                  <Checkbox name="remember" size="sm">
                    Remember me
                  </Checkbox>
                  <Link className="text-default-500" href="#">
                    Forgot password?
                  </Link>
                </div>
              )}
              {type === "sign-up" && (
                <>
                  <CustomInput
                    control={form.control}
                    name="confirmPassword"
                    confirmPassword
                  />
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
                            <Link href="#" size="sm">
                              Terms
                            </Link>
                            &nbsp; and&nbsp;
                            <Link href="#" size="sm">
                              Privacy Policy
                            </Link>
                          </Checkbox>
                        </FormControl>
                        <FormMessage className="text-system-error dark:text-system-error" />
                      </>
                    )}
                  />
                </>
              )}

              {state?.message === "Credentials error" && (
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
                disabled={isLoading}
              >
                {isLoading ? (
                  <span>Loading</span>
                ) : (
                  <span>{type === "sign-in" ? "Log In" : "Sign Up"}</span>
                )}
              </CustomButton>
            </form>
          </Form>

          {type === "sign-in" && (
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
          )}
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

      <div
        className="relative hidden w-1/2 flex-col-reverse rounded-medium p-10 shadow-small lg:flex"
        style={{
          backgroundImage:
            "url(https://nextuipro.nyc3.cdn.digitaloceanspaces.com/components-images/white-building.jpg)",
          backgroundSize: "cover",
          backgroundPosition: "center",
        }}
      >
        <div className="flex flex-col items-end gap-4">
          <p className="w-full text-right text-2xl text-black/60">
            <span className="font-normal">Open Source Security Platform</span>
          </p>
        </div>
      </div>
    </div>
  );
};
