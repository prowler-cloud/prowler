"use client";

import { type ComponentProps, type PointerEvent } from "react";

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
      className={cn("@container relative min-h-0 flex-1", className)}
      {...props}
    />
  );
}

interface SidePanelResizeHandleProps {
  // Receives the pointer's clientX on every drag move; the caller derives the
  // new width from it (for a right-anchored panel: viewport width - clientX).
  onResize: (clientX: number) => void;
  onResizeStart?: () => void;
  onResizeEnd?: () => void;
}

export function SidePanelResizeHandle({
  onResize,
  onResizeStart,
  onResizeEnd,
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

  const endResize = (event: PointerEvent<HTMLDivElement>) => {
    if (!event.currentTarget.hasPointerCapture(event.pointerId)) return;
    event.currentTarget.releasePointerCapture(event.pointerId);
    onResizeEnd?.();
  };

  return (
    <div
      role="separator"
      aria-orientation="vertical"
      aria-label="Resize panel"
      className="hover:bg-border-neutral-secondary active:bg-border-neutral-secondary absolute inset-y-0 left-0 z-10 w-1.5 cursor-col-resize touch-none transition-colors"
      onPointerDown={handlePointerDown}
      onPointerMove={handlePointerMove}
      onPointerUp={endResize}
      onPointerCancel={endResize}
    />
  );
}
