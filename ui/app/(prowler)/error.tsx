"use client";

import { useEffect } from "react";
import { Icon } from "@iconify/react";
import { RocketIcon } from "@/components/icons";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui";
import { CustomButton } from "@/components/ui/custom";
import { CustomLink } from "@/components/ui/custom/custom-link";

export default function Error({
  error,
  reset,
}: {
  error: Error & { digest?: string };
  reset: () => void;
}) {
  useEffect(() => {
    // Check if it's a 500 error
    const is500Error =
      error.message?.includes("500") ||
      error.message?.includes("502") ||
      error.message?.includes("503") ||
      error.message?.toLowerCase().includes("server error");

    if (is500Error) {
      // Log 500 errors specifically for monitoring
      console.error("Server error detected:", {
        message: error.message,
        digest: error.digest,
        timestamp: new Date().toISOString(),
      });
      // TODO: sent to sentry
    } else {
      console.error("Application error:", error);
    }
  }, [error]);

  const is500Error =
    error.message?.includes("500") ||
    error.message?.includes("502") ||
    error.message?.includes("503") ||
    error.message?.toLowerCase().includes("server error");

  return (
    <div className="flex min-h-screen items-center justify-center p-4">
      <Alert className="w-full max-w-lg">
        <Icon
          icon={is500Error ? "tabler:server-off" : "tabler:rocket-off"}
          className="h-5 w-5"
        />
        <AlertTitle className="text-lg">
          {is500Error
            ? "Server temporarily unavailable"
            : "An unexpected error occurred"}
        </AlertTitle>
        <AlertDescription className="mb-5">
          {is500Error
            ? "The server is experiencing issues. Our team has been notified and is working on it. Please try again in a few moments."
            : "We're sorry for the inconvenience. Please try again or contact support if the problem persists."}
        </AlertDescription>
        <div className="flex items-center justify-start gap-3">
          <CustomButton
            onPress={reset}
            variant="solid"
            color="primary"
            size="sm"
            startContent={<Icon icon="tabler:refresh" className="h-4 w-4" />}
            ariaLabel="Try Again"
          >
            Try Again
          </CustomButton>
          <CustomLink href="/" target="_self" className="font-bold">
            Go to Overview
          </CustomLink>
        </div>
      </Alert>
    </div>
  );
}
