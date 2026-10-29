"use client";

import { type ComponentProps, useRef } from "react";

import { Modal } from "@/components/shadcn/modal";
import { useMountEffect } from "@/hooks/use-mount-effect";
import { useSidePanelPushWidth } from "@/hooks/use-side-panel-push-width";
import { SIDE_PANEL_ELEMENT_ID } from "@/lib/ui-layout";
import { useSidePanelStore } from "@/store/side-panel";

type SidePanelHostModalProps = Omit<
  ComponentProps<typeof Modal>,
  "modal" | "insetRight" | "isInsetResizing" | "ref"
>;

function isInsideSidePanel(target: EventTarget | null): boolean {
  return (
    target instanceof Element &&
    target.closest(`#${SIDE_PANEL_ELEMENT_ID}`) !== null
  );
}

// A dialog that shares the screen with the global side panel: it centers in
// the space the panel leaves and nothing done in the panel can dismiss it.
export function SidePanelHostModal({
  onEscapeKeyDown,
  children,
  ...props
}: SidePanelHostModalProps) {
  const insetRight = useSidePanelPushWidth();
  const isResizing = useSidePanelStore((state) => state.isResizing);
  const contentRef = useRef<HTMLDivElement>(null);

  const handleEscapeKeyDown = (event: KeyboardEvent) => {
    onEscapeKeyDown?.(event);
    if (event.defaultPrevented || !isInsideSidePanel(event.target)) return;
    // Radix handles Escape first (document capture), so the panel's own
    // listener sees it prevented: close the panel here instead of the dialog.
    event.preventDefault();
    useSidePanelStore.getState().closePanel();
    contentRef.current?.focus();
  };

  return (
    <Modal
      {...props}
      ref={contentRef}
      modal={false}
      insetRight={insetRight}
      isInsetResizing={isResizing}
      onEscapeKeyDown={handleEscapeKeyDown}
    >
      <ModalHostRegistration />
      {children}
    </Modal>
  );
}

// Mounted with the dialog content, so it is registered exactly while open.
function ModalHostRegistration() {
  useMountEffect(() => useSidePanelStore.getState().registerModalHost());
  return null;
}
