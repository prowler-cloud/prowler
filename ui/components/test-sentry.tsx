"use client";

import * as Sentry from "@sentry/nextjs";

import { CustomButton } from "@/components/ui/custom";

export function TestSentry() {
  const testSentryError = () => {
    try {
      throw new Error("Test Sentry Error - This is a test error!");
    } catch (error) {
      Sentry.captureException(error, {
        tags: {
          test: true,
          component: "TestSentry",
        },
        level: "error",
      });
      // eslint-disable-next-line no-console
      console.log("Test error sent to Sentry!");
    }
  };

  const testSentryMessage = () => {
    Sentry.captureMessage("Test Sentry Message - Everything is working!", {
      level: "info",
      tags: {
        test: true,
        component: "TestSentry",
      },
    });
    // eslint-disable-next-line no-console
    console.log("Test message sent to Sentry!");
  };

  // Only show in development
  if (process.env.NODE_ENV !== "development") {
    return null;
  }

  return (
    <div className="fixed bottom-4 right-4 z-50 flex gap-2 rounded-lg border bg-background p-2 shadow-lg">
      <CustomButton
        size="sm"
        variant="ghost"
        color="warning"
        onPress={testSentryError}
        ariaLabel="Test Sentry Error"
      >
        Test Sentry Error
      </CustomButton>
      <CustomButton
        size="sm"
        variant="ghost"
        color="primary"
        onPress={testSentryMessage}
        ariaLabel="Test Sentry Message"
      >
        Test Sentry Message
      </CustomButton>
    </div>
  );
}
