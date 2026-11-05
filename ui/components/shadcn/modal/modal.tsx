"use client";

import {
  type FocusEvent,
  type ReactNode,
  type Ref,
  useRef,
  useState,
} from "react";

import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogPortal,
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
const preventOutsideDismiss = (event: Event) => event.preventDefault();

interface ModalBaseProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  title?: string;
  description?: string;
  children: ReactNode;
  size?: ModalSize;
  className?: string;
  ref?: Ref<HTMLDivElement>;
  onOpenAutoFocus?: (event: Event) => void;
  onCloseAutoFocus?: (event: Event) => void;
  onEscapeKeyDown?: (event: KeyboardEvent) => void;
  /**
   * Cap the dialog at 90dvh and scroll overflowing content, instead of
   * letting it grow past the viewport. Opt-in per modal (e.g. for content
   * whose height depends on user input) rather than a DS-wide default, so
   * existing modals keep their current sizing.
   */
  scrollable?: boolean;
}

interface ModalDefaultProps extends ModalBaseProps {
  modal?: true;
  insetRight?: never;
  isInsetResizing?: never;
}

// The page outside stays usable (e.g. a docked side panel): outside clicks and
// focus never dismiss it; only the backdrop, Escape and the close button do.
interface ModalNonModalProps extends ModalBaseProps {
  modal: false;
  // Pixels left uncovered at the right edge; the dialog centers in the rest.
  insetRight?: number;
  // Follow insetRight 1:1 (no easing) while it is being dragged.
  isInsetResizing?: boolean;
}

type ModalProps = ModalDefaultProps | ModalNonModalProps;

export const Modal = ({
  open,
  onOpenChange,
  title,
  description,
  children,
  size = "xl",
  className,
  ref,
  onOpenAutoFocus = preventInitialAutoFocus,
  onCloseAutoFocus,
  onEscapeKeyDown,
  scrollable = false,
  modal = true,
  insetRight,
  isInsetResizing = false,
}: ModalProps) => {
  // Non-modal frame: the content portals into it, so it is the containing
  // block (contain:layout traps the fixed dialog) and the container-query
  // reference for the whole dialog.
  const [frame, setFrame] = useState<HTMLDivElement | null>(null);
  const isNonModal = !modal;
  // Modal is always controlled, so Radix has no trigger to give focus back to.
  const openerRef = useRef<HTMLElement | null>(null);

  const handleOpenAutoFocus = (event: Event) => {
    openerRef.current =
      document.activeElement instanceof HTMLElement
        ? document.activeElement
        : null;
    onOpenAutoFocus(event);
  };

  // A self-focusing field skips Radix open autofocus: take the opener it left.
  const handleFocusCapture = (event: FocusEvent<HTMLDivElement>) => {
    const previous = event.relatedTarget;
    if (
      !openerRef.current &&
      previous instanceof HTMLElement &&
      !event.currentTarget.contains(previous)
    ) {
      openerRef.current = previous;
    }
  };

  const handleCloseAutoFocus = (event: Event) => {
    onCloseAutoFocus?.(event);
    const opener = openerRef.current;
    openerRef.current = null;
    if (event.defaultPrevented) return;
    event.preventDefault();
    opener?.focus({ preventScroll: true });
  };

  return (
    <Dialog open={open} onOpenChange={onOpenChange} modal={modal}>
      {isNonModal && (
        <DialogPortal forceMount>
          <div
            data-slot="modal-frame"
            data-responsive-container
            className={cn(
              "@container pointer-events-none fixed inset-y-0 left-0 z-50 [contain:layout]",
              !isInsetResizing && "transition-[right] duration-200 ease-out",
            )}
            style={{ right: insetRight ?? 0 }}
          >
            {/* Plain inner node: a ref through the portal's Slot would
                detach and reattach on every render. */}
            <div ref={setFrame} className="contents" />
          </div>
        </DialogPortal>
      )}
      {isNonModal && frame && (
        // Radix renders no overlay for non-modal dialogs: this is ours.
        <DialogPortal container={frame}>
          <div
            data-slot="modal-backdrop"
            data-state={open ? "open" : "closed"}
            aria-hidden
            className="data-[state=open]:animate-in data-[state=closed]:animate-out data-[state=closed]:fade-out-0 data-[state=open]:fade-in-0 pointer-events-auto absolute inset-0 bg-black/50"
            onClick={() => onOpenChange(false)}
          />
        </DialogPortal>
      )}
      {(!isNonModal || frame) && (
        <DialogContent
          ref={ref}
          container={isNonModal ? frame : undefined}
          onOpenAutoFocus={handleOpenAutoFocus}
          onCloseAutoFocus={handleCloseAutoFocus}
          onFocusCapture={handleFocusCapture}
          onEscapeKeyDown={onEscapeKeyDown}
          onInteractOutside={isNonModal ? preventOutsideDismiss : undefined}
          // Radix requires an accessible description; opt out explicitly when none is provided.
          {...(description ? {} : { "aria-describedby": undefined })}
          className={cn(
            "border-text-neutral-tertiary bg-bg-neutral-secondary rounded-[24px] border shadow-[0_0_200px_0_rgba(15,44,46,0.50)]",
            isNonModal && "pointer-events-auto outline-none",
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
      )}
    </Dialog>
  );
};
