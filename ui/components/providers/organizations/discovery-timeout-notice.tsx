"use client";

import { Clock } from "lucide-react";

import { Alert, AlertDescription } from "@/components/shadcn/alert";
import { Button } from "@/components/shadcn/button/button";

interface DiscoveryTimeoutNoticeProps {
  onKeepWaiting: () => void;
  onRetry: () => void;
}

/**
 * The worker keeps running past the client's polling budget, so a timeout offers
 * two actions: keep waiting (resume the same discovery) or retry (a fresh one).
 */
export function DiscoveryTimeoutNotice({
  onKeepWaiting,
  onRetry,
}: DiscoveryTimeoutNoticeProps) {
  return (
    <Alert variant="warning">
      <Clock className="size-4" />
      <AlertDescription>
        <div className="flex flex-col gap-3">
          <p>
            Discovery is taking longer than expected. It may still be running in
            the background.
          </p>
          <div className="flex gap-3">
            <Button
              type="button"
              variant="default"
              size="sm"
              onClick={onKeepWaiting}
            >
              Keep waiting
            </Button>
            <Button type="button" variant="outline" size="sm" onClick={onRetry}>
              Retry
            </Button>
          </div>
        </div>
      </AlertDescription>
    </Alert>
  );
}
