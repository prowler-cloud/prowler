"use client";

import { ArrowRight } from "lucide-react";
import Link from "next/link";
import { useRef, useState } from "react";

import { LighthouseIcon } from "@/components/icons/Icons";
import { Card, CardContent } from "@/components/shadcn";
import { useMountEffect } from "@/hooks/use-mount-effect";
import { cn } from "@/lib/utils";

import type { LighthouseOverviewBannerHref } from "../_lib/lighthouse-banner";

interface LighthouseOverviewBannerProps {
  href: LighthouseOverviewBannerHref;
}

export function LighthouseOverviewBanner({
  href,
}: LighthouseOverviewBannerProps) {
  const interactiveRef = useRef<HTMLDivElement>(null);
  const curXRef = useRef(0);
  const curYRef = useRef(0);
  const tgXRef = useRef(0);
  const tgYRef = useRef(0);
  const [isSafari, setIsSafari] = useState(false);

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
      className="group focus-visible:ring-border-input-primary block rounded-xl focus-visible:ring-2 focus-visible:ring-offset-2 focus-visible:outline-none"
    >
      <Card
        variant="base"
        padding="none"
        className="group-hover:border-border-input-primary relative overflow-hidden transition-colors"
        onMouseMove={handleMouseMove}
      >
        <svg className="hidden">
          <defs>
            <filter id="blurMe">
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
            "pointer-events-none absolute inset-0 blur-lg",
            isSafari ? "blur-2xl" : "[filter:url(#blurMe)_blur(40px)]",
          )}
        >
          <div className="animate-first lighthouse-banner-gradient-neutral absolute [top:calc(50%-60%)] [left:calc(50%-60%)] h-[120%] w-[120%] [transform-origin:center_center] opacity-100 [mix-blend-mode:hard-light]" />

          <div className="animate-second lighthouse-banner-gradient-primary absolute [top:calc(50%-60%)] [left:calc(50%-60%)] h-[120%] w-[120%] [transform-origin:calc(50%-200px)] opacity-80 [mix-blend-mode:hard-light]" />

          <div className="animate-third lighthouse-banner-gradient-primary-hover absolute [top:calc(50%-60%)] [left:calc(50%-60%)] h-[120%] w-[120%] [transform-origin:calc(50%+200px)] opacity-70 [mix-blend-mode:hard-light]" />

          <div
            ref={interactiveRef}
            className="lighthouse-banner-gradient-primary-press absolute -top-1/2 -left-1/2 h-full w-full opacity-60 [mix-blend-mode:hard-light]"
          />
        </div>

        <CardContent className="relative z-10 flex min-w-0 items-center justify-between gap-4 px-4 py-3 sm:px-5">
          <div className="flex min-w-0 items-center gap-3">
            <span className="border-border-neutral-tertiary bg-bg-neutral-tertiary flex size-9 shrink-0 items-center justify-center rounded-md border">
              <LighthouseIcon className="size-5" />
            </span>
            <div className="min-w-0">
              <p className="text-text-neutral-primary text-sm font-medium">
                Lighthouse AI
              </p>
              <p className="text-text-neutral-secondary text-sm">
                Find and remediate which actually matters.
              </p>
            </div>
          </div>
          <ArrowRight className="text-text-neutral-tertiary size-4 shrink-0 transition-transform group-hover:translate-x-0.5" />
        </CardContent>
      </Card>
    </Link>
  );
}
