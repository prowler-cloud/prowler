import { Button, CircularProgress } from "@nextui-org/react";
import type { PressEvent } from "@react-types/shared";
import clsx from "clsx";

import { NextUIColors, NextUIVariants } from "@/types";

export const buttonClasses = {
  base: "px-4 inline-flex items-center justify-center relative z-0 text-center whitespace-nowrap",
  primary: "bg-default-100 hover:bg-default-200 text-default-800",
  secondary: "bg-prowler-grey-light dark:bg-prowler-grey-medium text-white",
  action: "bg-prowler-theme-green font-bold text-prowler-theme-midnight",
  dashed:
    "border border-default border-dashed bg-transparent  justify-center whitespace-nowrap font-medium shadow-sm hover:border-solid hover:bg-default-100 active:bg-default-200 active:border-solid",
  transparent: "border-0 border-transparent bg-transparent",
  disabled: "pointer-events-none opacity-40",
  hover: "hover:shadow-md",
};

interface ButtonProps {
  type?: "button" | "submit" | "reset";
  ariaLabel: string;
  ariaDisabled?: boolean;
  className?: string;
  variant?:
    | "solid"
    | "faded"
    | "bordered"
    | "light"
    | "flat"
    | "ghost"
    | "dashed"
    | "shadow";
  color?:
    | "primary"
    | "secondary"
    | "action"
    | "success"
    | "warning"
    | "danger"
    | "transparent";
  onPress?: (e: PressEvent) => void;
  children: React.ReactNode;
  startContent?: React.ReactNode;
  endContent?: React.ReactNode;
  size?: "sm" | "md" | "lg";
  radius?: "none" | "sm" | "md" | "lg" | "full";
  dashed?: boolean;
  disabled?: boolean;
  isLoading?: boolean;
  isIconOnly?: boolean;
}

export const CustomButton = ({
  type = "button",
  ariaLabel,
  ariaDisabled,
  className,
  variant = "solid",
  color = "primary",
  onPress,
  children,
  startContent,
  endContent,
  size = "md",
  radius = "sm",
  disabled = false,
  isLoading = false,
  isIconOnly,
  ...props
}: ButtonProps) => (
  <Button
    type={type}
    aria-label={ariaLabel}
    aria-disabled={ariaDisabled}
    onPress={onPress}
    variant={variant as NextUIVariants}
    color={color as NextUIColors}
    className={clsx(
      buttonClasses.base,
      {
        [buttonClasses.primary]: color === "primary",
        [buttonClasses.secondary]: color === "secondary",
        [buttonClasses.action]: color === "action",
        [buttonClasses.dashed]: variant === "dashed",
        [buttonClasses.transparent]: color === "transparent",
        [buttonClasses.disabled]: disabled,
        [buttonClasses.hover]: color !== "transparent" && !disabled,
      },
      className,
    )}
    startContent={startContent}
    endContent={endContent}
    size={size}
    radius={radius}
    spinner={
      <CircularProgress
        classNames={{
          svg: "w-6 h-6 drop-shadow-md",
          indicator: "stroke-white",
          track: "stroke-white/10",
        }}
        aria-label="Loading..."
      />
    }
    isLoading={isLoading}
    isIconOnly={isIconOnly}
    {...props}
  >
    {children}
  </Button>
);
