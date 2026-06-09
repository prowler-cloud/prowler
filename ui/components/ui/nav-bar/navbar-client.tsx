"use client";

import { BellRing, Info } from "lucide-react";
import { usePathname, useRouter, useSearchParams } from "next/navigation";
import { ReactNode } from "react";

import {
  Button,
  Tooltip,
  TooltipContent,
  TooltipTrigger,
} from "@/components/shadcn";
import { ThemeSwitch } from "@/components/ThemeSwitch";
import { BreadcrumbNavigation } from "@/components/ui";
import { useSidebar } from "@/hooks/use-sidebar";
import { getFlowById } from "@/lib/onboarding";
import { isCloud } from "@/lib/shared/env";
import { useTourCompletion } from "@/lib/tours/use-tour-completion";
import { cn } from "@/lib/utils";
import { usePageReadyStore } from "@/store/page-ready";

import { SheetMenu } from "../sidebar/sheet-menu";
import { SidebarToggle } from "../sidebar/sidebar-toggle";
import { UserNav } from "../user-nav/user-nav";

export interface OnboardingActionConfig {
  flowId: string;
  fallbackFlowId?: string;
  useFallback?: boolean;
}

interface NavbarClientProps {
  title: string;
  icon?: string | ReactNode;
  onboardingAction?: OnboardingActionConfig;
  feedsSlot?: ReactNode;
}

export function NavbarClient({
  title,
  icon,
  onboardingAction,
  feedsSlot,
}: NavbarClientProps) {
  const { isOpen, toggleOpen } = useSidebar();
  const pathname = usePathname();
  const router = useRouter();
  const searchParams = useSearchParams();
  const targetFlowId =
    onboardingAction?.useFallback && onboardingAction.fallbackFlowId
      ? onboardingAction.fallbackFlowId
      : onboardingAction?.flowId;
  // Cloud-only: no flow → no replay icon in OSS.
  const flow =
    isCloud() && targetFlowId ? getFlowById(targetFlowId) : undefined;
  // Pulse only until the tour is seen; any close (completed/skipped/dismissed)
  // calms it. The replay button itself stays.
  const seen = useTourCompletion(flow?.tour ?? null) !== null;

  // Keep the replay icon disabled until this route's content has finished loading,
  // so a tour never starts before its anchors are in the DOM.
  const readyPath = usePageReadyStore((state) => state.readyPath);
  const pageReady = readyPath === pathname;

  const replayFlow = () => {
    if (!flow) return;

    const params =
      flow.route === pathname
        ? new URLSearchParams(searchParams?.toString())
        : new URLSearchParams();
    params.set("onboarding", flow.id);
    router.push(`${flow.route}?${params.toString()}`);
  };

  return (
    <header className="sticky top-0 z-10 w-full pt-4 backdrop-blur-sm">
      <div className="flex h-14 items-center pr-6">
        <div className="flex items-center gap-2">
          <SheetMenu />
          <div className="hidden lg:block">
            <SidebarToggle isOpen={isOpen} setIsOpen={toggleOpen} />
          </div>
          <BreadcrumbNavigation
            mode="auto"
            title={title}
            icon={icon}
            titleAction={
              // Hidden until the route's content has loaded, so the tour never starts
              // before its anchors exist (and we avoid a disabled-then-enabled flash).
              flow && pageReady ? (
                <Tooltip>
                  <TooltipTrigger asChild>
                    <Button
                      type="button"
                      variant="ghost"
                      size="icon-xs"
                      aria-label={`Start product tour: ${flow.title}`}
                      onClick={replayFlow}
                    >
                      <Info
                        className={cn(
                          "text-bg-data-info size-4",
                          !seen && "animate-pulse",
                        )}
                        aria-hidden="true"
                      />
                    </Button>
                  </TooltipTrigger>
                  <TooltipContent>See how it works</TooltipContent>
                </Tooltip>
              ) : null
            }
            paramToPreserve="scanId"
          />
        </div>
        <div className="flex flex-1 items-center justify-end gap-3">
          <ThemeSwitch />
          {feedsSlot}
          <UserNav />
        </div>
      </div>
    </header>
  );
}

export function FeedsLoadingFallback() {
  return (
    <Button
      variant="outline"
      className="border-border-input-primary-fill relative h-8 w-8 rounded-full bg-transparent p-2"
      disabled
    >
      <BellRing size={18} className="animate-pulse text-slate-400" />
    </Button>
  );
}
