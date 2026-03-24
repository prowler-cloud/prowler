import { ReactNode } from "react";

import {
  AlertDialog,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogHeader,
  AlertDialogTitle,
} from "@/components/shadcn/alert-dialog";
import { cn } from "@/lib/utils";

const SIZE_CLASSES = {
  sm: "sm:max-w-sm",
  md: "sm:max-w-md",
  lg: "sm:max-w-lg",
  xl: "sm:max-w-xl",
  "2xl": "sm:max-w-2xl",
  "3xl": "sm:max-w-3xl",
  "4xl": "sm:max-w-4xl",
  "5xl": "sm:max-w-5xl",
} as const;

type AlertModalSize = keyof typeof SIZE_CLASSES;

interface AlertModalProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  title?: string;
  description?: string;
  children: ReactNode;
  size?: AlertModalSize;
  className?: string;
}

export const AlertModal = ({
  open,
  onOpenChange,
  title,
  description,
  children,
  size = "xl",
  className,
}: AlertModalProps) => {
  return (
    <AlertDialog open={open} onOpenChange={onOpenChange}>
      <AlertDialogContent
        className={cn(
          "border-border-neutral-secondary bg-bg-neutral-secondary",
          SIZE_CLASSES[size],
          className,
        )}
      >
        {title && (
          <AlertDialogHeader>
            <AlertDialogTitle>{title}</AlertDialogTitle>
            {description && (
              <AlertDialogDescription className="text-small text-gray-600 dark:text-gray-300">
                {description}
              </AlertDialogDescription>
            )}
          </AlertDialogHeader>
        )}
        {children}
      </AlertDialogContent>
    </AlertDialog>
  );
};
