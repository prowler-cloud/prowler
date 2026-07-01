import { CircleAlert, Info } from "lucide-react";
import type { ReactNode } from "react";

import { Alert, AlertDescription, AlertTitle } from "@/components/shadcn/alert";

const STATUS_ALERT_ICONS = {
  info: Info,
  error: CircleAlert,
} as const;

type StatusAlertVariant = keyof typeof STATUS_ALERT_ICONS;

interface StatusAlertProps {
  variant: StatusAlertVariant;
  title: string;
  descriptionClassName?: string;
  children: ReactNode;
}

/**
 * Shared status banner: a shadcn `Alert` with a variant-driven icon, title, and
 * description. Use for full-width info/error messages (waiting states, load
 * failures, inline notices).
 */
export const StatusAlert = ({
  variant,
  title,
  descriptionClassName,
  children,
}: StatusAlertProps) => {
  const Icon = STATUS_ALERT_ICONS[variant];
  return (
    <Alert variant={variant}>
      <Icon className="size-4" />
      <AlertTitle>{title}</AlertTitle>
      <AlertDescription className={descriptionClassName}>
        {children}
      </AlertDescription>
    </Alert>
  );
};
