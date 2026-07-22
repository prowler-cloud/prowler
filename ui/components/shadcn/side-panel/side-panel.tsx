"use client";

import {
  type ComponentProps,
  type KeyboardEvent,
  type PointerEvent,
} from "react";

import { cn } from "@/lib/utils";

// Base right-hand side panel primitive: a fixed shell that slides in from the
// right without a backdrop (non-modal). Presentation only — open state, tabs
// and content wiring live in the caller (see components/side-panel/).

interface SidePanelProps extends ComponentProps<"aside"> {
  open: boolean;
}

export function SidePanel({
  open,
  className,
  children,
  ...props
}: SidePanelProps) {
  return (
    <aside
      role="complementary"
      inert={!open}
      className={cn(
        "border-border-neutral-secondary bg-bg-neutral-secondary fixed inset-y-0 right-0 z-40 flex flex-col border-l shadow-xl transition-[transform,width] duration-200",
        open ? "translate-x-0" : "translate-x-full",
        className,
      )}
      {...props}
    >
      {children}
    </aside>
  );
}

export function SidePanelHeader({
  className,
  ...props
}: ComponentProps<"div">) {
  return (
    <div
      className={cn(
        "border-border-neutral-secondary flex items-center gap-1 border-b px-3 py-2",
        className,
      )}
      {...props}
    />
  );
}

export function SidePanelBody({ className, ...props }: ComponentProps<"div">) {
  return (
    <div
      // @container: content hosted in the panel (detail tables, the chat)
      // resolves its breakpoints against the panel's width, not the viewport.
      data-responsive-container
      className={cn("@container relative min-h-0 flex-1", className)}
      {...props}
    />
  );
}

// Width added/removed per arrow-key press when resizing via keyboard.
const KEYBOARD_RESIZE_STEP = 24;

interface SidePanelResizeHandleProps {
  // Receives the pointer's clientX on every drag move; the caller derives the
  // new width from it (for a right-anchored panel: viewport width - clientX)
  // and clamps it.
  onResize: (clientX: number) => void;
  onResizeStart?: () => void;
  onResizeEnd?: () => void;
  // Current width and bounds for the ARIA window-splitter contract and to
  // derive keyboard steps.
  value: number;
  min: number;
  max: number;
}

export function SidePanelResizeHandle({
  onResize,
  onResizeStart,
  onResizeEnd,
  value,
  min,
  max,
}: SidePanelResizeHandleProps) {
  const handlePointerDown = (event: PointerEvent<HTMLDivElement>) => {
    event.preventDefault();
    event.currentTarget.setPointerCapture(event.pointerId);
    onResizeStart?.();
  };

  const handlePointerMove = (event: PointerEvent<HTMLDivElement>) => {
    if (!event.currentTarget.hasPointerCapture(event.pointerId)) return;
    onResize(event.clientX);
  };

  // Idempotent: also reached via onLostPointerCapture (capture already gone),
  // e.g. when Escape closes the panel mid-drag and pointerup never arrives.
  const endResize = (event: PointerEvent<HTMLDivElement>) => {
    if (event.currentTarget.hasPointerCapture(event.pointerId)) {
      event.currentTarget.releasePointerCapture(event.pointerId);
    }
    onResizeEnd?.();
  };

  // WAI-ARIA window splitter: arrows move the handle as a drag would, so on
  // this right-docked panel ArrowLeft widens and ArrowRight narrows.
  const handleKeyDown = (event: KeyboardEvent<HTMLDivElement>) => {
    if (event.key !== "ArrowLeft" && event.key !== "ArrowRight") return;
    event.preventDefault();
    const step =
      event.key === "ArrowLeft" ? KEYBOARD_RESIZE_STEP : -KEYBOARD_RESIZE_STEP;
    // Same contract as a drag: report the clientX the handle would land on.
    onResize(window.innerWidth - (value + step));
  };

  return (
    <div
      role="separator"
      tabIndex={0}
      aria-orientation="vertical"
      aria-label="Resize panel"
      aria-valuemin={min}
      aria-valuemax={max}
      aria-valuenow={Math.round(value)}
      className="hover:bg-border-neutral-secondary active:bg-border-neutral-secondary focus-visible:ring-button-primary/50 absolute inset-y-0 left-0 z-10 w-1.5 cursor-col-resize touch-none transition-colors outline-none focus-visible:ring-2"
      onPointerDown={handlePointerDown}
      onPointerMove={handlePointerMove}
      onPointerUp={endResize}
      onPointerCancel={endResize}
      onLostPointerCapture={endResize}
      onKeyDown={handleKeyDown}
    />
  );
}
