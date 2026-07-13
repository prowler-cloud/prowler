"use client";

import { useTheme } from "next-themes";
import { ComponentProps, useSyncExternalStore } from "react";

import {
  Tooltip,
  TooltipContent,
  TooltipTrigger,
} from "@/components/shadcn/tooltip";
import { cn } from "@/lib/utils";

import { MoonFilledIcon, SunFilledIcon } from "./icons";

export type ThemeSwitchProps = ComponentProps<"button">;

const emptySubscribe = () => () => {};

export function ThemeSwitch({ className, ...props }: ThemeSwitchProps) {
  const { theme, setTheme } = useTheme();
  // Hydration-safe mounted check: false on the server, true after hydration
  const isHydrated = useSyncExternalStore(
    emptySubscribe,
    () => true,
    () => false,
  );

  const isLightMode = theme === "light" || !isHydrated;

  return (
    <Tooltip>
      <TooltipTrigger asChild>
        <button
          type="button"
          {...props}
          role="switch"
          aria-checked={isLightMode}
          aria-label={`Switch to ${isLightMode ? "dark" : "light"} mode`}
          onClick={() => setTheme(isLightMode ? "dark" : "light")}
          className={cn(
            "text-neutral-tertiary flex cursor-pointer items-center justify-center rounded-lg px-px pt-px transition-opacity hover:opacity-80",
            className,
          )}
        >
          {isLightMode && isHydrated ? (
            <MoonFilledIcon size={22} />
          ) : (
            <SunFilledIcon size={22} />
          )}
        </button>
      </TooltipTrigger>
      <TooltipContent>
        {isLightMode ? "Switch to Dark Mode" : "Switch to Light Mode"}
      </TooltipContent>
    </Tooltip>
  );
}
