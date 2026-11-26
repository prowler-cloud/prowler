"use client";

import { LockKeyhole } from "lucide-react";
import Link from "next/link";

import { Button } from "@/components/shadcn/button/button";
import { PREMIUM_PAGE_PATH } from "@/lib/premium";

import type { AppSidebarSelectionHandler } from "./types";

interface SidebarFooterProps {
  isCloudEnvironment: boolean;
  onSelect?: AppSidebarSelectionHandler;
}

export function SidebarFooter({
  isCloudEnvironment,
  onSelect,
}: SidebarFooterProps) {
  const version = process.env.NEXT_PUBLIC_PROWLER_RELEASE_VERSION;

  return (
    <div className="shrink-0 px-3 pb-4">
      {!isCloudEnvironment && (
        <div className="pt-4 pb-3">
          <Button asChild variant="outline" className="w-full">
            <Link href={PREMIUM_PAGE_PATH} onClick={onSelect}>
              <LockKeyhole aria-hidden="true" className="size-4" />
              Compare editions
            </Link>
          </Button>
        </div>
      )}

      <div className="border-border-neutral-secondary text-text-neutral-tertiary flex min-h-9 items-center border-t pt-3 text-[11px]">
        {!isCloudEnvironment && (
          <span className="min-w-0 flex-1 truncate">
            Open Source · Apache-2.0
          </span>
        )}
        {isCloudEnvironment && (
          <Link
            href="https://status.prowler.com"
            target="_blank"
            rel="noopener noreferrer"
            className="hover:text-text-neutral-primary min-w-0 flex-1 transition-colors"
            onClick={onSelect}
          >
            <span className="truncate">Service status</span>
          </Link>
        )}
        <span className="ml-auto font-mono">{version}</span>
      </div>
    </div>
  );
}
