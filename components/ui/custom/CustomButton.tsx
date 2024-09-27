import { Button, CircularProgress } from "@nextui-org/react";
import clsx from "clsx";

export const buttonClasses = {
  base: "px-2 inline-flex items-center justify-center relative z-0 text-center whitespace-nowrap",
  primary: "bg-default-100 hover:bg-default-200 text-default-800",
  secondary: "bg-prowler-grey-light dark:bg-prowler-grey-medium text-white",
  action: "text-white bg-prowler-blue-smoky dark:bg-prowler-grey-medium",
  dashed:
    "border border-default border-dashed bg-transparent hover:bg-accent justify-center whitespace-nowrap font-medium shadow-sm hover:bg-accent hover:text-accent-foreground",
  transparent: "border-0 border-transparent bg-transparent",
  disabled: "pointer-events-none opacity-40",
  hover: "hover:shadow-md",
};

interface ButtonProps {
  type?: "button" | "submit" | "reset";
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
  onPress?: (event: React.MouseEvent<HTMLButtonElement>) => void;
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
    onPress={onPress}
    variant={variant}
    color={color}
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
    spinner={<CircularProgress aria-label="Loading..." size="sm" />}
    isLoading={isLoading}
    isIconOnly={isIconOnly}
    {...props}
  >
    {children}
  </Button>
);
