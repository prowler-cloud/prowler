"use client";

import { useTheme } from "next-themes";
import { ComponentProps, useSyncExternalStore } from "react";

import { Button } from "@/components/shadcn/button/button";
import {
  Tooltip,
  TooltipContent,
  TooltipTrigger,
} from "@/components/shadcn/tooltip";

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
        <Button
          type="button"
          {...props}
          variant="ghost"
          size="icon-sm"
          role="switch"
          aria-checked={isLightMode}
          aria-label={`Switch to ${isLightMode ? "dark" : "light"} mode`}
          onClick={() => setTheme(isLightMode ? "dark" : "light")}
          className={className}
        >
          {isLightMode && isHydrated ? (
            <MoonFilledIcon className="size-5" />
          ) : (
            <SunFilledIcon className="size-5" />
          )}
        </Button>
      </TooltipTrigger>
      <TooltipContent>
        {isLightMode ? "Switch to Dark Mode" : "Switch to Light Mode"}
      </TooltipContent>
    </Tooltip>
  );
}
