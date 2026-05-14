"use client";

import { Icon } from "@iconify/react";
import * as Sentry from "@sentry/nextjs";
import { useEffect } from "react";

import { Button } from "@/components/shadcn";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/shadcn/card/card";
import { CustomLink } from "@/components/ui/custom/custom-link";
import { SentryErrorSource, SentryErrorType } from "@/sentry";

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

      // Send to Sentry with high priority
      Sentry.captureException(error, {
        tags: {
          error_boundary: "app",
          error_type: SentryErrorType.SERVER_ERROR,
          error_source: SentryErrorSource.ERROR_BOUNDARY,
          status_code: "500",
          digest: error.digest,
        },
        level: "error",
        fingerprint: ["server-error", error.message],
        contexts: {
          error_details: {
            is_server_error: true,
            timestamp: new Date().toISOString(),
          },
        },
      });
    } else {
      console.error("Application error:", error);

      // Send other errors to Sentry with normal priority
      Sentry.captureException(error, {
        tags: {
          error_boundary: "app",
          error_type: SentryErrorType.APPLICATION_ERROR,
          error_source: SentryErrorSource.ERROR_BOUNDARY,
          digest: error.digest,
        },
        level: "warning",
        fingerprint: ["app-error", error.message],
      });
    }
  }, [error]);

  const is500Error =
    error.message?.includes("500") ||
    error.message?.includes("502") ||
    error.message?.includes("503") ||
    error.message?.toLowerCase().includes("server error");

  return (
    <div className="flex min-h-screen items-center justify-center p-4">
      <Card variant="base" className="w-full max-w-lg">
        <CardHeader>
          <div className="flex items-start gap-3">
            <Icon
              icon={is500Error ? "tabler:server-off" : "tabler:rocket-off"}
              className="mt-0.5 h-5 w-5 flex-shrink-0 text-red-500"
            />
            <div className="flex flex-col gap-2">
              <CardTitle className="text-lg">
                {is500Error
                  ? "Server temporarily unavailable"
                  : "An unexpected error occurred"}
              </CardTitle>
              <CardDescription className="text-sm">
                {is500Error
                  ? "The server is experiencing issues. Our team has been notified and is working on it. Please try again in a few moments."
                  : "We're sorry for the inconvenience. Please try again or contact support if the problem persists."}
              </CardDescription>
            </div>
          </div>
        </CardHeader>
        <CardContent>
          <div className="flex items-center justify-start gap-3">
            <Button onClick={reset} size="sm" className="gap-2">
              <Icon icon="tabler:refresh" className="h-4 w-4" />
              Try Again
            </Button>
            <CustomLink href="/" target="_self" className="font-bold">
              Go to Overview
            </CustomLink>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
