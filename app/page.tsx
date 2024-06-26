"use client";

import React from "react";
import {
  Card,
  CardHeader,
  CardBody,
  CardFooter,
  Input,
  Link,
  Button,
} from "@nextui-org/react";
import { EyeIcon } from "@heroicons/react/24/solid";
import { EyeSlashIcon } from "@heroicons/react/24/solid";

export default function Home() {
  const [isVisible, setIsVisible] = React.useState(false);

  const toggleVisibility = () => setIsVisible(!isVisible);

  return (
    <section className="flex flex-col items-center justify-center gap-4 py-8 md:py-10">
      <div className="inline-block max-w-lg text-center justify-center">
        <Card>
          <CardHeader className="pb-0">
            <h1 className="pl-1">Login</h1>
          </CardHeader>
          <CardBody className="w-72 pb-0">
            <Input
              label="Email"
              variant="bordered"
              placeholder="Enter your email"
              className="mb-2"
            />
            <Input
              label="Password"
              variant="bordered"
              placeholder="Enter your password"
              endContent={
                <button
                  className="focus:outline-none"
                  type="button"
                  onClick={toggleVisibility}
                >
                  {isVisible ? (
                    <EyeSlashIcon className="text-2xl text-default-400 pointer-events-none w-5 h-5" />
                  ) : (
                    <EyeIcon className="text-2xl text-default-400 pointer-events-none w-5 h-5" />
                  )}
                </button>
              }
              type={isVisible ? "text" : "password"}
              className="max-w-xs"
            />
          </CardBody>
          <CardFooter>
            <Button href="/clouds" as={Link} color="primary">
              Submit
            </Button>
          </CardFooter>
        </Card>
        <p className="mt-24">This is a page with "use client", useState</p>
      </div>
    </section>
  );
}
