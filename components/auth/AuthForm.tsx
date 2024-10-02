"use client";

import { zodResolver } from "@hookform/resolvers/zod";
import { Icon } from "@iconify/react";
import { Button, Checkbox, Divider, Link } from "@nextui-org/react";
import { useRouter } from "next/navigation";
import { useEffect } from "react";
import { useFormState } from "react-dom";
import { useForm } from "react-hook-form";
import { z } from "zod";

import { authenticate } from "@/actions";
import {
  Form,
  FormControl,
  FormField,
  FormMessage,
} from "@/components/ui/form";
import { authFormSchema } from "@/types";

import { NotificationIcon, ProwlerExtended } from "../icons";
import { ThemeSwitch } from "../ThemeSwitch";
import { CustomInput } from "../ui/custom";
import { AuthButton } from "./AuthButton";

export const AuthForm = ({ type }: { type: string }) => {
  const formSchema = authFormSchema(type);
  const router = useRouter();
  const form = useForm<z.infer<typeof formSchema>>({
    resolver: zodResolver(formSchema),
    defaultValues: {
      email: "",
      password: "",
      ...(type === "sign-up" && {
        firstName: "",
        companyName: "",
        confirmPassword: "",
      }),
    },
  });

  const [state, dispatch] = useFormState(authenticate, undefined);

  useEffect(() => {
    if (state?.message === "Success") {
      router.push("/");
    }
  }, [state]);

  const onSubmit = async (data: z.infer<typeof formSchema>) => {
    // Do something with the form values
    // this will be type-safe and validated
    try {
      // Sign-up logic will be here.
      if (type === "sign-in") {
        console.log(data);
        dispatch({
          email: data.email.toLowerCase(),
          password: data.password,
        });
      }
      if (type === "sign-up") {
        console.log(data);
        // const newUser = await signUp(data);
      }
    } catch (error) {
      // eslint-disable-next-line no-console
      console.error(error);
    }
  };

  return (
    <div
      className="flex h-screen w-screen items-center justify-start overflow-hidden rounded-small bg-content1 p-2 sm:p-4 lg:p-8"
      style={{
        backgroundImage:
          "url(https://nextuipro.nyc3.cdn.digitaloceanspaces.com/components-images/black-background-texture-2.jpg)",
        backgroundSize: "cover",
        backgroundPosition: "center",
      }}
    >
      {/* Brand Logo and ThemeSwitch */}
      <div className="absolute right-10 top-10">
        <div className="flex items-center gap-4 self-center">
          <ThemeSwitch aria-label="Toggle theme" />
          <ProwlerExtended />
        </div>
      </div>

      {/* Testimonial */}
      <div className="absolute bottom-10 right-10 hidden md:block">
        <p className="text-md max-w-xl text-right text-white/60">
          <span className="font-medium">“</span>
          Open Cloud Security
          <span className="font-medium">”</span>
        </p>
      </div>

      <div className="flex w-full max-w-sm flex-col gap-4 rounded-large bg-content1 px-8 pb-10 pt-6 shadow-small">
        <p className="pb-2 text-xl font-medium">
          {type === "sign-in" ? "Sign In" : "Sign Up"}
        </p>

        <Form {...form}>
          <form
            className="flex flex-col gap-3"
            onSubmit={form.handleSubmit(onSubmit)}
          >
            {type === "sign-up" && (
              <>
                <CustomInput
                  control={form.control}
                  name="firstName"
                  type="text"
                  label="Name"
                  placeholder="Enter your name"
                />
                <CustomInput
                  control={form.control}
                  name="companyName"
                  type="text"
                  label="Company Name"
                  placeholder="Enter your company name"
                  isRequired={false}
                />
              </>
            )}
            <CustomInput
              control={form.control}
              name="email"
              type="email"
              label="Email"
              placeholder="Enter your email"
            />

            <CustomInput control={form.control} name="password" password />

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
              <FormField
                control={form.control}
                name="termsAndConditions"
                render={({ field }) => (
                  <>
                    <CustomInput
                      control={form.control}
                      name="confirmPassword"
                      confirmPassword
                    />
                    <FormControl>
                      <Checkbox
                        isRequired
                        className="py-4"
                        size="sm"
                        checked={field.value === "true"}
                        onChange={(e) =>
                          field.onChange(e.target.checked ? "true" : "false")
                        }
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
            )}

            {state?.message === "Credentials error" && (
              <div className="flex flex-row items-center gap-2 text-system-error">
                <NotificationIcon size={16} />
                <p className="text-s">Incorrect email or password</p>
              </div>
            )}

            <AuthButton type={type} />
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
  );
};
