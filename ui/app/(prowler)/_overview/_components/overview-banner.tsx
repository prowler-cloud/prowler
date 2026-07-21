"use client";

import { ArrowRight, Bot } from "lucide-react";
import Link from "next/link";
import { type ReactNode, useId, useRef, useState } from "react";

import { LighthouseIcon } from "@/components/icons/Icons";
import { Card, CardContent } from "@/components/shadcn";
import { useMountEffect } from "@/hooks/use-mount-effect";
import { cn } from "@/lib/utils";

import {
  OVERVIEW_BANNER_VARIANT,
  type OverviewBannerVariant,
} from "../_lib/overview-banner";

// Content lives here rather than at the call site so the icons stay inside the
// client boundary — LighthouseIcon uses useId and cannot render on the server.
const OVERVIEW_BANNER_CONTENT = {
  lighthouse: {
    icon: <LighthouseIcon className="size-5" />,
    title: "Lighthouse AI",
    description: "Find and remediate what actually matters.",
  },
  agents: {
    icon: <Bot className="size-5" />,
    title: "Connect all your agents to Prowler Cloud",
    description: "Turn your favorite agent into a Cloud Security Expert.",
  },
} as const satisfies Record<
  OverviewBannerVariant,
  { icon: ReactNode; title: string; description: string }
>;

interface OverviewBannerProps {
  variant: OverviewBannerVariant;
  href: string;
}

export function OverviewBanner({ variant, href }: OverviewBannerProps) {
  const { icon, title, description } = OVERVIEW_BANNER_CONTENT[variant];
  // Absolute hrefs leave the app, so they open in a new tab.
  const isExternal = href.startsWith("http");
  const interactiveRef = useRef<HTMLDivElement>(null);
  const curXRef = useRef(0);
  const curYRef = useRef(0);
  const tgXRef = useRef(0);
  const tgYRef = useRef(0);
  const [isSafari, setIsSafari] = useState(false);
  // Several banners render per page and url(#id) resolves against the FIRST
  // matching id in the document, so the filter id must be per-instance.
  const blurFilterId = `overview-banner-blur-${useId().replace(/[«»:]/g, "")}`;

  useMountEffect(() => {
    setIsSafari(/^((?!chrome|android).)*safari/i.test(navigator.userAgent));
  });

  useMountEffect(() => {
    let animationFrameId: number;

    const move = () => {
      if (!interactiveRef.current) return;

      curXRef.current += (tgXRef.current - curXRef.current) / 20;
      curYRef.current += (tgYRef.current - curYRef.current) / 20;

      interactiveRef.current.style.transform = `translate(${Math.round(curXRef.current)}px, ${Math.round(curYRef.current)}px)`;

      animationFrameId = requestAnimationFrame(move);
    };

    animationFrameId = requestAnimationFrame(move);

    return () => {
      cancelAnimationFrame(animationFrameId);
    };
  });

  const handleMouseMove = (event: React.MouseEvent<HTMLDivElement>) => {
    if (interactiveRef.current) {
      const rect = interactiveRef.current.getBoundingClientRect();
      tgXRef.current = event.clientX - rect.left;
      tgYRef.current = event.clientY - rect.top;
    }
  };

  return (
    <Link
      href={href}
      {...(isExternal
        ? { target: "_blank", rel: "noopener noreferrer" }
        : undefined)}
      className="group focus-visible:ring-border-input-primary block h-full rounded-xl focus-visible:ring-2 focus-visible:ring-offset-2 focus-visible:outline-none"
    >
      <Card
        variant="base"
        padding="none"
        // isolate: the content's internal z-10 (above the gradient layers)
        // must not compete with the page's sticky header, which is also z-10.
        className="group-hover:border-border-input-primary relative isolate h-full overflow-hidden transition-colors"
        onMouseMove={handleMouseMove}
      >
        <svg className="hidden">
          <defs>
            <filter id={blurFilterId}>
              <feGaussianBlur
                in="SourceGraphic"
                stdDeviation="10"
                result="blur"
              />
              <feColorMatrix
                in="blur"
                mode="matrix"
                values="1 0 0 0 0  0 1 0 0 0  0 0 1 0 0  0 0 0 18 -8"
                result="goo"
              />
              <feBlend in="SourceGraphic" in2="goo" />
            </filter>
          </defs>
        </svg>

        <div
          className={cn(
            "overview-banner-gradient pointer-events-none absolute inset-0 blur-lg",
            variant === OVERVIEW_BANNER_VARIANT.AGENTS
              ? "overview-banner-gradient-agents"
              : undefined,
            isSafari ? "blur-2xl" : undefined,
          )}
          style={
            isSafari
              ? undefined
              : { filter: `url(#${blurFilterId}) blur(40px)` }
          }
        >
          <div className="animate-first overview-banner-gradient-neutral absolute [top:calc(50%-60%)] [left:calc(50%-60%)] h-[120%] w-[120%] [transform-origin:center_center] opacity-100 [mix-blend-mode:hard-light]" />

          <div className="animate-second overview-banner-gradient-primary absolute [top:calc(50%-60%)] [left:calc(50%-60%)] h-[120%] w-[120%] [transform-origin:calc(50%-200px)] opacity-80 [mix-blend-mode:hard-light]" />

          <div className="animate-third overview-banner-gradient-primary-hover absolute [top:calc(50%-60%)] [left:calc(50%-60%)] h-[120%] w-[120%] [transform-origin:calc(50%+200px)] opacity-70 [mix-blend-mode:hard-light]" />

          <div
            ref={interactiveRef}
            className="overview-banner-gradient-primary-press absolute -top-1/2 -left-1/2 h-full w-full opacity-60 [mix-blend-mode:hard-light]"
          />
        </div>

        <CardContent className="relative z-10 flex h-full min-w-0 items-center justify-between gap-4 px-4 py-3 sm:px-5">
          <div className="flex min-w-0 items-center gap-3">
            <span className="border-border-neutral-tertiary bg-bg-neutral-tertiary flex size-9 shrink-0 items-center justify-center rounded-md border">
              {icon}
            </span>
            <div className="min-w-0">
              <p className="text-text-neutral-primary text-sm font-medium">
                {title}
              </p>
              <p className="text-text-neutral-secondary text-sm">
                {description}
              </p>
            </div>
          </div>
          <ArrowRight className="text-text-neutral-tertiary size-4 shrink-0 transition-transform group-hover:translate-x-0.5" />
        </CardContent>
      </Card>
    </Link>
  );
}
