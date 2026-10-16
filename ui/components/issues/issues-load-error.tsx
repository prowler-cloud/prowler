"use client";

import { useRouter } from "next/navigation";
import { useTransition } from "react";

import { Alert, AlertDescription, AlertTitle } from "@/components/shadcn/alert";
import { Button } from "@/components/shadcn/button/button";

interface IssuesLoadErrorProps {
  message?: string;
  onRetry?: () => void;
}

export function IssuesLoadError({
  message = "Failed to load issues.",
  onRetry,
}: IssuesLoadErrorProps) {
  const router = useRouter();
  const [pending, startTransition] = useTransition();
  return (
    <Alert variant="error">
      <AlertTitle>{message}</AlertTitle>
      <AlertDescription>
        <Button
          variant="outline"
          size="sm"
          disabled={pending}
          onClick={() =>
            startTransition(() => (onRetry ? onRetry() : router.refresh()))
          }
        >
          {pending ? "Retrying…" : "Retry"}
        </Button>
      </AlertDescription>
    </Alert>
  );
}
