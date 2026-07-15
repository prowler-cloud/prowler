"use client";

import { ScanLine } from "lucide-react";
import Link from "next/link";
import { usePathname } from "next/navigation";

import { Button } from "@/components/shadcn/button/button";
import { LAUNCH_SCAN_HREF } from "@/lib/scans-navigation";
import { useScansStore } from "@/store";

import type { AppSidebarSelectionHandler } from "./types";

interface LaunchScanActionProps {
  onSelect?: AppSidebarSelectionHandler;
}

function LaunchScanContent() {
  return (
    <>
      <ScanLine aria-hidden="true" className="size-5" />
      <span>Launch Scan</span>
    </>
  );
}

export function LaunchScanAction({ onSelect }: LaunchScanActionProps) {
  const pathname = usePathname();
  const openLaunchScanModal = useScansStore(
    (state) => state.openLaunchScanModal,
  );
  const isScansPage = pathname.startsWith("/scans");

  if (isScansPage) {
    return (
      <Button
        type="button"
        variant="primary-glow"
        size="sidebar"
        className="w-full"
        aria-label="Launch Scan"
        onClick={() => {
          openLaunchScanModal();
          onSelect?.();
        }}
      >
        <LaunchScanContent />
      </Button>
    );
  }

  return (
    <Button asChild variant="primary-glow" size="sidebar" className="w-full">
      <Link href={LAUNCH_SCAN_HREF} aria-label="Launch Scan" onClick={onSelect}>
        <LaunchScanContent />
      </Link>
    </Button>
  );
}
