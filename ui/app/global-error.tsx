"use client";

import * as Sentry from "@sentry/nextjs";
import NextError from "next/error";
import { useEffect } from "react";

import { SentryErrorSource, SentryErrorType } from "@/sentry";

export default function GlobalError({
  error,
  reset: _reset,
}: {
  error: Error & { digest?: string };
  reset: () => void;
}) {
  useEffect(() => {
    Sentry.captureException(error, {
      tags: {
        error_boundary: "global",
        error_type: SentryErrorType.APPLICATION_ERROR,
        error_source: SentryErrorSource.ERROR_BOUNDARY,
        digest: error.digest,
      },
      level: "error",
      contexts: {
        react: {
          componentStack: error.stack,
        },
      },
    });
  }, [error]);

  return (
    <html lang="en">
      <body>
        <NextError statusCode={500} />
      </body>
    </html>
  );
}
