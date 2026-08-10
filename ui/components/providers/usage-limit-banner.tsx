"use client";

import { AlertTriangle } from "lucide-react";
import Link from "next/link";
import { useEffect, useState } from "react";

import {
  Alert,
  AlertDescription,
  AlertTitle,
  Button,
} from "@/components/shadcn";

const STORAGE_KEY = "usage-limit-banner-dismissed";

interface UsageLimitBannerProps {
  allowHide?: boolean;
  showBillingButton?: boolean;
}

export const UsageLimitBanner = ({
  allowHide = false,
  showBillingButton = true,
}: UsageLimitBannerProps) => {
  const [isVisible, setIsVisible] = useState<boolean | null>(null);

  useEffect(() => {
    const isDismissed = sessionStorage.getItem(STORAGE_KEY) === "true";
    setIsVisible(!isDismissed);
  }, []);

  const handleClose = () => {
    sessionStorage.setItem(STORAGE_KEY, "true");
    setIsVisible(false);
  };

  // Don't render until we've checked sessionStorage (prevents hydration mismatch)
  if (isVisible === null || !isVisible) return null;

  return (
    <Alert
      variant="warning"
      onClose={allowHide ? handleClose : undefined}
      className="animate-fade-in"
    >
      <AlertTriangle />
      <AlertTitle>Usage limit exceeded</AlertTitle>
      <AlertDescription className="flex flex-col gap-3 sm:flex-row sm:items-end sm:justify-between">
        <span>
          You have exceeded the usage limit of one provider. You can add more
          providers and run unlimited scans by adding a subscription.
        </span>
        {showBillingButton && (
          <Button
            asChild
            variant="secondary"
            size="sm"
            className="w-fit shrink-0"
          >
            <Link href="/billing">Manage Billing</Link>
          </Button>
        )}
      </AlertDescription>
    </Alert>
  );
};
