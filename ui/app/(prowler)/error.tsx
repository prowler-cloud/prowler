"use client";

import { useEffect } from "react";

import { RocketIcon } from "@/components/icons";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui";
import { CustomLink } from "@/components/ui/custom";

export default function Error({
  error,
  // reset,
}: {
  error: Error;
  reset: () => void;
}) {
  useEffect(() => {
    // Log the error to an error reporting service
    /* eslint-disable no-console */
    console.error(error);
  }, [error]);

  return (
    <Alert className="mx-auto mt-[35%] w-fit">
      <RocketIcon className="h-5 w-5" />
      <AlertTitle className="text-lg">An unexpected error occurred</AlertTitle>
      <AlertDescription className="mb-5">
        We&apos;re sorry for the inconvenience. Please try again or contact
        support if the problem persists.
      </AlertDescription>
      <CustomLink href="/" target="_self" className="font-bold">
        Go to the homepage
      </CustomLink>
    </Alert>
  );
}
