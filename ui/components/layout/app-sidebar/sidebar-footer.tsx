"use client";

import Link from "next/link";

import type { AppSidebarSelectionHandler } from "./types";

interface SidebarFooterProps {
  isCloudEnvironment: boolean;
  onSelect?: AppSidebarSelectionHandler;
}

export function SidebarFooter({
  isCloudEnvironment,
  onSelect,
}: SidebarFooterProps) {
  const version =
    process.env.NEXT_PUBLIC_CLOUDY_RELEASE_VERSION ??
    process.env.NEXT_PUBLIC_PROWLER_RELEASE_VERSION;

  return (
    <div className="shrink-0 px-3 pb-4">
      <div className="border-border-neutral-secondary text-text-neutral-tertiary flex min-h-9 items-center border-t pt-3 text-[11px]">
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
