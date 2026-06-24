"use client";

import Link from "next/link";
import { useEffect, useRef, useState } from "react";

import { Card, CardContent } from "@/components/shadcn/card/card";
import { cn } from "@/lib/utils";

import { LighthouseIcon } from "../icons";

const AnimatedGradientCard = ({
  message,
  href,
}: {
  message: string;
  href: string;
}) => {
  const interactiveRef = useRef<HTMLDivElement>(null);
  const curXRef = useRef(0);
  const curYRef = useRef(0);
  const tgXRef = useRef(0);
  const tgYRef = useRef(0);
  const [isSafari, setIsSafari] = useState(false);

  useEffect(() => {
    setIsSafari(/^((?!chrome|android).)*safari/i.test(navigator.userAgent));
  }, []);

  useEffect(() => {
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
  }, []);

  const handleMouseMove = (event: React.MouseEvent<HTMLDivElement>) => {
    if (interactiveRef.current) {
      const rect = interactiveRef.current.getBoundingClientRect();
      tgXRef.current = event.clientX - rect.left;
      tgYRef.current = event.clientY - rect.top;
    }
  };

  return (
    <Link href={href} className="mb-8 block w-full">
      <Card
        variant="base"
        className="group relative overflow-hidden"
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
          <div className="animate-first absolute [top:calc(50%-60%)] [left:calc(50%-60%)] h-[120%] w-[120%] [transform-origin:center_center] opacity-100 [mix-blend-mode:hard-light] [background:radial-gradient(circle_at_center,_var(--bg-neutral-tertiary)_0,_transparent_50%)_no-repeat]" />

          <div className="animate-second absolute [top:calc(50%-60%)] [left:calc(50%-60%)] h-[120%] w-[120%] [transform-origin:calc(50%-200px)] opacity-80 [mix-blend-mode:hard-light] [background:radial-gradient(circle_at_center,_var(--bg-button-primary)_0,_transparent_50%)_no-repeat]" />

          <div className="animate-third absolute [top:calc(50%-60%)] [left:calc(50%-60%)] h-[120%] w-[120%] [transform-origin:calc(50%+200px)] opacity-70 [mix-blend-mode:hard-light] [background:radial-gradient(circle_at_center,_var(--bg-button-primary-hover)_0,_transparent_50%)_no-repeat]" />

          <div
            ref={interactiveRef}
            className="absolute -top-1/2 -left-1/2 h-full w-full opacity-60 [mix-blend-mode:hard-light] [background:radial-gradient(circle_at_center,_var(--bg-button-primary-press)_0,_transparent_50%)_no-repeat]"
          />
        </div>

        <CardContent className="relative z-10">
          <div className="flex items-center gap-4">
            <div className="flex h-10 w-10 items-center justify-center">
              <LighthouseIcon size={24} />
            </div>
            <p className="text-text-neutral-primary text-base font-semibold">
              {message}
            </p>
          </div>
        </CardContent>
      </Card>
    </Link>
  );
};

export const LighthouseBannerClient = ({
  isConfigured,
}: {
  isConfigured: boolean;
}) => {
  const message = isConfigured
    ? "Use Lighthouse to review your findings and gain insights"
    : "Enable Lighthouse to secure your cloud with AI insights";
  const href = isConfigured ? "/lighthouse" : "/lighthouse/config";

  return <AnimatedGradientCard message={message} href={href} />;
};
