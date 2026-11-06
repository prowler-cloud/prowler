"use client";

import { CloudCog, ScanLine } from "lucide-react";
import Link from "next/link";
import { usePathname } from "next/navigation";

import { Button } from "@/components/shadcn/button/button";
import { useAuth } from "@/hooks";
import {
  dispatchProviderFunnel,
  PROVIDER_FUNNEL_STEP,
  SIDEBAR_CTA_VARIANT,
  WIZARD_OPEN_SOURCE,
} from "@/lib/provider-funnel/provider-funnel-events";
import { buildAddProviderHref } from "@/lib/providers-navigation";
import { LAUNCH_SCAN_HREF } from "@/lib/scans-navigation";
import { useScansStore } from "@/store";
import { useUIStore } from "@/store/ui/store";

import type { AppSidebarSelectionHandler } from "./types";

const ADD_PROVIDER_FROM_SIDEBAR_HREF = buildAddProviderHref(
  WIZARD_OPEN_SOURCE.SIDEBAR_CTA,
);

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
  const { permissions } = useAuth();
  // Only a confirmed empty tenant swaps the action; an unresolved count keeps Launch Scan.
  const hasNoProviders = useUIStore(
    (state) => state.hasProvidersResolved && !state.hasProviders,
  );
  // Without the permission an empty list may just be limited visibility.
  const needsFirstProvider =
    hasNoProviders && permissions.manage_providers === true;
  const isScansPage = pathname.startsWith("/scans");

  if (needsFirstProvider) {
    return (
      <Button asChild size="lg" className="w-full">
        <Link
          href={ADD_PROVIDER_FROM_SIDEBAR_HREF}
          aria-label="Add Provider"
          onClick={() => {
            dispatchProviderFunnel({
              step: PROVIDER_FUNNEL_STEP.SIDEBAR_CTA_CLICKED,
              variant: SIDEBAR_CTA_VARIANT.ADD_PROVIDER,
            });
            onSelect?.();
          }}
        >
          <CloudCog aria-hidden="true" className="size-5" />
          <span>Add Provider</span>
        </Link>
      </Button>
    );
  }

  const trackLaunchScan = () =>
    dispatchProviderFunnel({
      step: PROVIDER_FUNNEL_STEP.SIDEBAR_CTA_CLICKED,
      variant: SIDEBAR_CTA_VARIANT.LAUNCH_SCAN,
    });

  if (isScansPage) {
    return (
      <Button
        type="button"
        size="lg"
        className="w-full"
        aria-label="Launch Scan"
        onClick={() => {
          trackLaunchScan();
          openLaunchScanModal();
          onSelect?.();
        }}
      >
        <LaunchScanContent />
      </Button>
    );
  }

  return (
    <Button asChild size="lg" className="w-full">
      <Link
        href={LAUNCH_SCAN_HREF}
        aria-label="Launch Scan"
        onClick={() => {
          trackLaunchScan();
          onSelect?.();
        }}
      >
        <LaunchScanContent />
      </Link>
    </Button>
  );
}
