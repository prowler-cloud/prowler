"use client";

import { ArrowRight, Sparkles } from "lucide-react";
import Link from "next/link";
import { type CSSProperties, type PointerEvent, useRef } from "react";

import { Badge } from "@/components/shadcn/badge/badge";
import { Card } from "@/components/shadcn/card/card";
import { cn } from "@/lib/utils";

export const TRIAL_SIDEBAR_BANNER_VARIANT = {
  ACTIVE_DAYS: "active_days",
  ACTIVE_SCANS: "active_scans",
  ACTIVE_UNLIMITED: "active_unlimited",
  EXPIRED: "expired",
} as const;

interface TrialSidebarBannerBaseProps {
  onSelect?: () => HTMLElement | null;
}

interface ActiveTrialSidebarBannerProps extends TrialSidebarBannerBaseProps {
  remaining: number;
}

interface ActiveDaysTrialSidebarBannerProps
  extends ActiveTrialSidebarBannerProps {
  variant: typeof TRIAL_SIDEBAR_BANNER_VARIANT.ACTIVE_DAYS;
}

interface ActiveScansTrialSidebarBannerProps
  extends ActiveTrialSidebarBannerProps {
  variant: typeof TRIAL_SIDEBAR_BANNER_VARIANT.ACTIVE_SCANS;
}

interface ActiveUnlimitedTrialSidebarBannerProps
  extends TrialSidebarBannerBaseProps {
  variant: typeof TRIAL_SIDEBAR_BANNER_VARIANT.ACTIVE_UNLIMITED;
  remaining?: never;
}

interface ExpiredTrialSidebarBannerProps extends TrialSidebarBannerBaseProps {
  variant: typeof TRIAL_SIDEBAR_BANNER_VARIANT.EXPIRED;
  remaining?: never;
}

export type TrialSidebarBannerProps =
  | ActiveDaysTrialSidebarBannerProps
  | ActiveScansTrialSidebarBannerProps
  | ActiveUnlimitedTrialSidebarBannerProps
  | ExpiredTrialSidebarBannerProps;

const TRIAL_URGENCY = {
  HEALTHY: "healthy",
  WARNING: "warning",
  CRITICAL: "critical",
} as const;

type TrialUrgency = (typeof TRIAL_URGENCY)[keyof typeof TRIAL_URGENCY];

const TRIAL_SIDEBAR_BANNER_UNIT = {
  DAY: "day",
  SCAN: "scan",
} as const;

type TrialSidebarBannerUnit =
  (typeof TRIAL_SIDEBAR_BANNER_UNIT)[keyof typeof TRIAL_SIDEBAR_BANNER_UNIT];

interface TrialUrgencyStyles {
  sidebarBorder: string;
  sidebarTint: string;
  sidebarGlow: string;
}

const TRIAL_URGENCY_STYLES: Record<TrialUrgency, TrialUrgencyStyles> = {
  [TRIAL_URGENCY.HEALTHY]: {
    sidebarBorder: "border-button-primary",
    sidebarTint: "bg-button-primary/10",
    sidebarGlow: "bg-button-primary/20",
  },
  [TRIAL_URGENCY.WARNING]: {
    sidebarBorder: "border-bg-warning",
    sidebarTint: "bg-bg-warning-secondary/20",
    sidebarGlow: "bg-bg-warning/20",
  },
  [TRIAL_URGENCY.CRITICAL]: {
    sidebarBorder: "border-border-error",
    sidebarTint: "bg-bg-fail-secondary/40",
    sidebarGlow: "bg-bg-fail/20",
  },
};

const getTrialUrgency = (props: TrialSidebarBannerProps): TrialUrgency => {
  if (props.variant === TRIAL_SIDEBAR_BANNER_VARIANT.EXPIRED) {
    return TRIAL_URGENCY.CRITICAL;
  }
  if (
    props.variant === TRIAL_SIDEBAR_BANNER_VARIANT.ACTIVE_SCANS &&
    props.remaining > 0
  ) {
    return TRIAL_URGENCY.HEALTHY;
  }
  if (props.variant === TRIAL_SIDEBAR_BANNER_VARIANT.ACTIVE_UNLIMITED) {
    return TRIAL_URGENCY.HEALTHY;
  }
  if (props.remaining <= 1) return TRIAL_URGENCY.CRITICAL;
  if (props.remaining <= 5) return TRIAL_URGENCY.WARNING;
  return TRIAL_URGENCY.HEALTHY;
};

const formatRemaining = (remaining: number, unit: TrialSidebarBannerUnit) =>
  `${remaining} ${unit}${remaining === 1 ? "" : "s"} left`;

export const TrialSidebarBanner = (props: TrialSidebarBannerProps) => {
  const cardRef = useRef<HTMLAnchorElement>(null);
  const isExpired = props.variant === TRIAL_SIDEBAR_BANNER_VARIANT.EXPIRED;
  const isScanBased =
    props.variant === TRIAL_SIDEBAR_BANNER_VARIANT.ACTIVE_SCANS;
  const urgency = getTrialUrgency(props);
  const urgencyStyles = TRIAL_URGENCY_STYLES[urgency];
  const remainingCopy = isExpired
    ? null
    : props.variant === TRIAL_SIDEBAR_BANNER_VARIANT.ACTIVE_UNLIMITED
      ? "Trial active"
      : formatRemaining(
          props.remaining,
          isScanBased
            ? TRIAL_SIDEBAR_BANNER_UNIT.SCAN
            : TRIAL_SIDEBAR_BANNER_UNIT.DAY,
        );

  const resetMotion = () => {
    const card = cardRef.current;
    if (!card) return;

    card.style.setProperty("--trial-rotate-x", "0deg");
    card.style.setProperty("--trial-rotate-y", "0deg");
    card.style.setProperty("--trial-lift", "0px");
    card.style.setProperty("--trial-pointer-x", "50%");
    card.style.setProperty("--trial-pointer-y", "50%");
  };

  const followPointer = (event: PointerEvent<HTMLAnchorElement>) => {
    if (
      event.pointerType === "touch" ||
      window.matchMedia?.("(prefers-reduced-motion: reduce)").matches
    ) {
      return;
    }

    const card = cardRef.current;
    if (!card) return;

    const bounds = card.getBoundingClientRect();
    const pointerX = event.clientX - bounds.left;
    const pointerY = event.clientY - bounds.top;
    const normalizedX = pointerX / bounds.width - 0.5;
    const normalizedY = pointerY / bounds.height - 0.5;

    card.style.setProperty("--trial-rotate-x", `${normalizedY * -3}deg`);
    card.style.setProperty("--trial-rotate-y", `${normalizedX * 4}deg`);
    card.style.setProperty("--trial-lift", "-2px");
    card.style.setProperty("--trial-pointer-x", `${pointerX}px`);
    card.style.setProperty("--trial-pointer-y", `${pointerY}px`);
  };

  const motionStyles = {
    "--trial-rotate-x": "0deg",
    "--trial-rotate-y": "0deg",
    "--trial-lift": "0px",
    "--trial-pointer-x": "50%",
    "--trial-pointer-y": "50%",
    transform:
      "perspective(700px) rotateX(var(--trial-rotate-x)) rotateY(var(--trial-rotate-y)) translateY(var(--trial-lift))",
  } as CSSProperties;

  return (
    <Link
      ref={cardRef}
      href="/billing"
      aria-label={
        isExpired
          ? "Explore plans after your trial expired"
          : isScanBased
            ? "Explore plans for your free trial"
            : "Explore plans for your unlimited trial"
      }
      onClick={props.onSelect}
      onPointerMove={followPointer}
      onPointerLeave={resetMotion}
      onBlur={resetMotion}
      style={motionStyles}
      className="focus-visible:ring-button-primary/50 group mx-3 mb-4 block rounded-xl transition-transform duration-200 ease-out focus-visible:ring-2 focus-visible:outline-none motion-reduce:transform-none motion-reduce:transition-none"
    >
      <Card
        variant="inner"
        padding="sm"
        data-slot="sidebar-trial"
        data-urgency={urgency}
        role="status"
        aria-label={isExpired ? "Expired trial" : "Active trial"}
        aria-live="polite"
        className={cn(
          "relative gap-3 overflow-hidden transition-colors duration-200",
          urgencyStyles.sidebarBorder,
          urgencyStyles.sidebarTint,
        )}
      >
        <span
          data-slot="trial-glow"
          aria-hidden="true"
          className={cn(
            "pointer-events-none absolute size-32 rounded-full opacity-0 blur-3xl transition-opacity duration-300 group-hover:opacity-100 motion-reduce:hidden",
            urgencyStyles.sidebarGlow,
          )}
          style={{
            left: "var(--trial-pointer-x)",
            top: "var(--trial-pointer-y)",
            transform: "translate(-50%, -50%)",
          }}
        />
        <div className="relative z-10 flex min-w-0 items-start gap-2.5">
          <span className="border-border-neutral-tertiary bg-bg-neutral-secondary flex size-9 shrink-0 items-center justify-center rounded-md border">
            <Sparkles
              className={cn(
                "size-4",
                isExpired ? "text-text-error-primary" : "text-button-primary",
              )}
              aria-hidden="true"
            />
          </span>
          <div className="flex min-w-0 flex-1 flex-col gap-1.5">
            <Badge
              variant={isExpired ? "error" : "success"}
              size="sm"
              className="w-fit"
            >
              {isExpired
                ? "Trial expired"
                : isScanBased
                  ? "Free trial"
                  : "Unlimited trial"}
            </Badge>
            <strong className="text-text-neutral-primary text-lg leading-none">
              {isExpired ? "Subscription required" : remainingCopy}
            </strong>
          </div>
        </div>
        <p className="text-text-neutral-secondary relative z-10 text-xs leading-4">
          {isExpired
            ? "Subscribe to continue scanning and running scheduled scans."
            : isScanBased
              ? "Choose a plan to keep running scans after your trial ends."
              : "Unlimited accounts, scans, and daily schedules. Subscribe to keep everything running."}
        </p>
        <span className="text-button-primary relative z-10 flex items-center justify-between text-xs font-semibold">
          Explore plans
          <ArrowRight
            className="size-4 transition-transform duration-200 group-hover:translate-x-0.5 motion-reduce:transform-none"
            aria-hidden="true"
          />
        </span>
      </Card>
    </Link>
  );
};
