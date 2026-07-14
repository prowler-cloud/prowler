"use client";

import { Upload } from "lucide-react";
import Link from "next/link";
import { useState } from "react";

import { Alert, AlertTitle } from "@/components/shadcn";
import { useMountEffect } from "@/hooks/use-mount-effect";
import { DOCS_URLS } from "@/lib/external-urls";
import { cn } from "@/lib/utils";

const STORAGE_KEY = "prowler:cli-import-banner-dismissed";

interface CliImportBannerProps {
  className?: string;
  href?: string;
}

export const CliImportBanner = ({
  className,
  href = DOCS_URLS.FINDINGS_INGESTION,
}: CliImportBannerProps) => {
  const [isVisible, setIsVisible] = useState<boolean | null>(null);
  const opensInNewTab = href.startsWith("http");

  useMountEffect(() => {
    const isDismissed = localStorage.getItem(STORAGE_KEY) === "true";
    setIsVisible(!isDismissed);
  });

  const handleClose = () => {
    localStorage.setItem(STORAGE_KEY, "true");
    setIsVisible(false);
  };

  if (isVisible === null || !isVisible) return null;

  return (
    <Alert
      variant="info"
      onClose={handleClose}
      className={cn("animate-fade-in", className)}
    >
      <Upload />
      <AlertTitle>
        Import findings from Prowler CLI -{" "}
        <Link
          href={href}
          target={opensInNewTab ? "_blank" : undefined}
          rel={opensInNewTab ? "noopener noreferrer" : undefined}
          className="font-normal underline underline-offset-2"
        >
          Learn more
        </Link>
      </AlertTitle>
    </Alert>
  );
};
