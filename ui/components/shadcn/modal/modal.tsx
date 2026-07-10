import { ReactNode } from "react";

import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from "@/components/shadcn/dialog";
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

type ModalSize = keyof typeof SIZE_CLASSES;

const preventInitialAutoFocus = (event: Event) => event.preventDefault();

interface ModalProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  title?: string;
  description?: string;
  children: ReactNode;
  size?: ModalSize;
  className?: string;
  onOpenAutoFocus?: (event: Event) => void;
  /**
   * Cap the dialog at 90dvh and scroll overflowing content, instead of
   * letting it grow past the viewport. Opt-in per modal (e.g. for content
   * whose height depends on user input) rather than a DS-wide default, so
   * existing modals keep their current sizing.
   */
  scrollable?: boolean;
}

export const Modal = ({
  open,
  onOpenChange,
  title,
  description,
  children,
  size = "xl",
  className,
  onOpenAutoFocus = preventInitialAutoFocus,
  scrollable = false,
}: ModalProps) => {
  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent
        onOpenAutoFocus={onOpenAutoFocus}
        // Radix requires an accessible description; opt out explicitly when none is provided.
        {...(description ? {} : { "aria-describedby": undefined })}
        className={cn(
          "border-text-neutral-tertiary bg-bg-neutral-secondary rounded-[24px] border shadow-[0_0_200px_0_rgba(15,44,46,0.50)]",
          scrollable && "max-h-[90dvh] overflow-y-auto",
          SIZE_CLASSES[size],
          className,
        )}
      >
        {title && (
          <DialogHeader>
            <DialogTitle>{title}</DialogTitle>
            {description && (
              <DialogDescription className="text-sm text-gray-600 dark:text-gray-300">
                {description}
              </DialogDescription>
            )}
          </DialogHeader>
        )}
        {children}
      </DialogContent>
    </Dialog>
  );
};
