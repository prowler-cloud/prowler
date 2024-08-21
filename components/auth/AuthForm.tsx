"use client";

import { Icon } from "@iconify/react";
import { Button, Checkbox, Divider, Input, Link } from "@nextui-org/react";
import { useState } from "react";
import { useFormState } from "react-dom";

import { authenticate } from "@/actions";

import { ProwlerExtended } from "../icons";
import { ThemeSwitch } from "../ThemeSwitch";
import { AuthButton } from "./AuthButton";

export const AuthForm = ({ type }: { type: string }) => {
  const [isVisible, setIsVisible] = useState(false);

  const [state, dispath] = useFormState(authenticate, undefined);
  console.log(state);

  const toggleVisibility = () => setIsVisible(!isVisible);

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
        <div className="flex items-center self-center gap-4">
          <ThemeSwitch aria-label="Toggle theme" />
          <ProwlerExtended />
        </div>
      </div>

      {/* Testimonial */}
      <div className="absolute bottom-10 right-10 hidden md:block">
        <p className="max-w-xl text-right text-white/60">
          <span className="font-medium">“</span>
          Lorem ipsum dolor sit amet, consectetur adipiscing elit. Nunc eget
          augue nec massa volutpat aliquet.
          <span className="font-medium">”</span>
        </p>
      </div>

      {/* Login Form */}
      <div className="flex w-full max-w-sm flex-col gap-4 rounded-large bg-content1 px-8 pb-10 pt-6 shadow-small">
        <p className="pb-2 text-xl font-medium">
          {type === "sign-in" ? "Sign In" : "Sign Up"}
        </p>
        <form className="flex flex-col gap-3" action={dispath}>
          <Input
            label="Email Address"
            name="email"
            placeholder="Enter your email"
            type="email"
            variant="bordered"
          />
          <Input
            endContent={
              <button type="button" onClick={toggleVisibility}>
                {isVisible ? (
                  <Icon
                    className="pointer-events-none text-2xl text-default-400"
                    icon="solar:eye-closed-linear"
                  />
                ) : (
                  <Icon
                    className="pointer-events-none text-2xl text-default-400"
                    icon="solar:eye-bold"
                  />
                )}
              </button>
            }
            label="Password"
            name="password"
            placeholder="Enter your password"
            type={isVisible ? "text" : "password"}
            variant="bordered"
          />
          <div className="flex items-center justify-between px-1 py-2">
            <Checkbox name="remember" size="sm">
              Remember me
            </Checkbox>
            <Link className="text-default-500" href="#">
              Forgot password?
            </Link>
          </div>
          <AuthButton type={type} />
        </form>
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
