"use client";

import {
  motion,
  useMotionValue,
  useReducedMotion,
  useSpring,
  useTransform,
} from "framer-motion";
import { ArrowRight, Sparkles } from "lucide-react";
import Link from "next/link";
import { type PointerEvent } from "react";

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

type TrialSidebarBannerVariant =
  (typeof TRIAL_SIDEBAR_BANNER_VARIANT)[keyof typeof TRIAL_SIDEBAR_BANNER_VARIANT];

type MeteredTrialVariant = Extract<
  TrialSidebarBannerProps,
  { remaining: number }
>["variant"];

interface TrialSidebarBannerCopy {
  badge: string;
  body: string;
  linkLabel: string;
  cardLabel: string;
}

const UNLIMITED_COPY = {
  badge: "Unlimited trial",
  body: "Unlimited accounts, scans, and daily schedules. Subscribe to keep everything running.",
  linkLabel: "Explore plans for your unlimited trial",
  cardLabel: "Active trial",
} as const satisfies TrialSidebarBannerCopy;

// Keyed maps rather than ternaries: a new variant fails to compile until every
// string and unit is supplied for it.
const TRIAL_SIDEBAR_BANNER_COPY: Record<
  TrialSidebarBannerVariant,
  TrialSidebarBannerCopy
> = {
  [TRIAL_SIDEBAR_BANNER_VARIANT.ACTIVE_DAYS]: UNLIMITED_COPY,
  [TRIAL_SIDEBAR_BANNER_VARIANT.ACTIVE_UNLIMITED]: UNLIMITED_COPY,
  [TRIAL_SIDEBAR_BANNER_VARIANT.ACTIVE_SCANS]: {
    badge: "Free trial",
    body: "Choose a plan to keep running scans after your trial ends.",
    linkLabel: "Explore plans for your free trial",
    cardLabel: "Active trial",
  },
  [TRIAL_SIDEBAR_BANNER_VARIANT.EXPIRED]: {
    badge: "Trial expired",
    body: "Subscribe to continue scanning and running scheduled scans.",
    linkLabel: "Explore plans after your trial expired",
    cardLabel: "Expired trial",
  },
};

const TRIAL_SIDEBAR_BANNER_METER: Record<
  MeteredTrialVariant,
  TrialSidebarBannerUnit
> = {
  [TRIAL_SIDEBAR_BANNER_VARIANT.ACTIVE_DAYS]: TRIAL_SIDEBAR_BANNER_UNIT.DAY,
  [TRIAL_SIDEBAR_BANNER_VARIANT.ACTIVE_SCANS]: TRIAL_SIDEBAR_BANNER_UNIT.SCAN,
};

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

const formatRemaining = (remaining: number, unit: TrialSidebarBannerUnit) => {
  // The API sends a cap and a usage counter, so callers subtract and can go negative.
  const left = Math.max(0, remaining);

  return `${left} ${unit}${left === 1 ? "" : "s"} left`;
};

const TILT_SPRING = { stiffness: 260, damping: 26, mass: 0.6 } as const;
const TILT_RESTING_POINTER = 0.5;
const TILT_RANGE_X = 1.5;
const TILT_RANGE_Y = 2;
const TILT_LIFT = -2;

export const TrialSidebarBanner = (props: TrialSidebarBannerProps) => {
  const isExpired = props.variant === TRIAL_SIDEBAR_BANNER_VARIANT.EXPIRED;
  const isScanBased =
    props.variant === TRIAL_SIDEBAR_BANNER_VARIANT.ACTIVE_SCANS;
  // The backend keeps a scan-capped trial `active` once its quota is spent.
  const isExhausted = isScanBased && props.remaining <= 0;
  const urgency = getTrialUrgency(props);
  const urgencyStyles = TRIAL_URGENCY_STYLES[urgency];
  const copy = TRIAL_SIDEBAR_BANNER_COPY[props.variant];
  const heading = isExpired
    ? "Subscription required"
    : props.variant === TRIAL_SIDEBAR_BANNER_VARIANT.ACTIVE_UNLIMITED
      ? "Trial active"
      : formatRemaining(
          props.remaining,
          TRIAL_SIDEBAR_BANNER_METER[props.variant],
        );

  const prefersReducedMotion = useReducedMotion();

  // Normalised pointer position (0..1) over the card.
  const pointerX = useMotionValue(TILT_RESTING_POINTER);
  const pointerY = useMotionValue(TILT_RESTING_POINTER);
  const hover = useMotionValue(0);

  const rotateX = useSpring(
    useTransform(pointerY, [0, 1], [TILT_RANGE_X, -TILT_RANGE_X]),
    TILT_SPRING,
  );
  const rotateY = useSpring(
    useTransform(pointerX, [0, 1], [-TILT_RANGE_Y, TILT_RANGE_Y]),
    TILT_SPRING,
  );
  const lift = useSpring(
    useTransform(hover, [0, 1], [0, TILT_LIFT]),
    TILT_SPRING,
  );
  const glowLeft = useTransform(pointerX, (value) => `${value * 100}%`);
  const glowTop = useTransform(pointerY, (value) => `${value * 100}%`);

  const resetMotion = () => {
    pointerX.set(TILT_RESTING_POINTER);
    pointerY.set(TILT_RESTING_POINTER);
    hover.set(0);
  };

  const followPointer = (event: PointerEvent<HTMLAnchorElement>) => {
    if (prefersReducedMotion || event.pointerType === "touch") return;

    const bounds = event.currentTarget.getBoundingClientRect();
    if (!bounds.width || !bounds.height) return;

    pointerX.set((event.clientX - bounds.left) / bounds.width);
    pointerY.set((event.clientY - bounds.top) / bounds.height);
    hover.set(1);
  };

  return (
    <Link
      href="/billing"
      aria-label={copy.linkLabel}
      onClick={props.onSelect}
      onPointerMove={followPointer}
      onPointerLeave={resetMotion}
      onPointerCancel={resetMotion}
      onBlur={resetMotion}
      className="focus-visible:ring-button-primary/50 group mx-3 mb-4 block rounded-xl focus-visible:ring-2 focus-visible:outline-none"
    >
      <motion.div
        className="rounded-xl"
        style={{ transformPerspective: 700, rotateX, rotateY, y: lift }}
      >
        <Card
          variant="inner"
          padding="sm"
          data-slot="sidebar-trial"
          data-urgency={urgency}
          role="status"
          aria-label={copy.cardLabel}
          // role="status" is implicitly atomic, which re-reads the whole card
          // on every counter change.
          aria-atomic="false"
          className={cn(
            "relative gap-3 overflow-hidden transition-colors duration-200",
            urgencyStyles.sidebarBorder,
            urgencyStyles.sidebarTint,
          )}
        >
          <motion.span
            data-slot="trial-glow"
            aria-hidden="true"
            className={cn(
              "pointer-events-none absolute size-32 rounded-full opacity-0 blur-3xl transition-opacity duration-300 group-hover:opacity-100 motion-reduce:hidden",
              urgencyStyles.sidebarGlow,
            )}
            style={{ left: glowLeft, top: glowTop, x: "-50%", y: "-50%" }}
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
                variant={isExpired || isExhausted ? "error" : "success"}
                size="sm"
                className="w-fit"
              >
                {copy.badge}
              </Badge>
              <strong className="text-text-neutral-primary text-lg leading-none">
                {heading}
              </strong>
            </div>
          </div>
          <p className="text-text-neutral-secondary relative z-10 text-xs leading-4">
            {copy.body}
          </p>
          <span className="text-button-primary relative z-10 flex items-center justify-between text-xs font-semibold">
            Explore plans
            <ArrowRight
              className="size-4 transition-transform duration-200 group-hover:translate-x-0.5 motion-reduce:transform-none"
              aria-hidden="true"
            />
          </span>
        </Card>
      </motion.div>
    </Link>
  );
};
