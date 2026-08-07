"use client";

import { type ReactNode, useState } from "react";
import { createPortal } from "react-dom";

import { useMountEffect } from "@/hooks/use-mount-effect";
import { useLighthouseContextStore } from "@/store/lighthouse-context/store";
import { useSidePanelStore } from "@/store/side-panel";
import type { LighthouseContextItem } from "@/types/lighthouse-context";

interface DetailSidePanelProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  // Screen-reader heading; the visible tab label is always "Details".
  title: string;
  description?: string;
  context?: LighthouseContextItem;
  children: ReactNode;
}

// Hosts a detail view (finding/resource) inside the global side panel as its
// "Details" context tab. The owning table keeps ALL detail state (selection,
// carousel, fetch caches) — only the rendered output moves into the panel via
// a portal, so the AI tab and the detail view share one panel, PostHog-style.
// Drop-in replacement for the old vaul detail drawers: same open/onOpenChange
// contract, no modal overlay.
export function DetailSidePanel({
  open,
  ...activeProps
}: DetailSidePanelProps) {
  // Mount/unmount IS the registration lifecycle: no dependency effects needed.
  if (!open) return null;
  return <DetailSidePanelActive {...activeProps} />;
}

function DetailSidePanelActive({
  onOpenChange,
  title,
  description,
  context,
  children,
}: Omit<DetailSidePanelProps, "open">) {
  // Owner token from registration: several detail views can be mounted at
  // once (one per table row); only the current owner may portal or unregister.
  const [token, setToken] = useState<number | null>(null);

  useMountEffect(() => {
    const registered = useSidePanelStore.getState().registerContextTab({
      label: "Details",
      // Mount-scoped capture is safe: the component remounts per open cycle
      // and every consumer's close path ends in stable setters.
      onRequestClose: () => onOpenChange(false),
    });
    useLighthouseContextStore
      .getState()
      .setFocusedContext(registered, context ?? null);
    setToken(registered);
    return () => {
      useLighthouseContextStore.getState().clearFocusedContext(registered);
      useSidePanelStore.getState().unregisterContextTab(registered);
    };
  });

  const ownerToken = useSidePanelStore((state) => state.contextOwnerToken);
  const outlet = useSidePanelStore((state) => state.contextOutlet);
  const focusedRegistration =
    context && token !== null ? (
      <FocusedContextRegistration
        key={`${token}:${JSON.stringify(context)}`}
        ownerToken={token}
        context={context}
      />
    ) : null;

  if (!outlet || token === null || token !== ownerToken) {
    return focusedRegistration;
  }

  return (
    <>
      {focusedRegistration}
      {createPortal(
        <div className="flex h-full min-h-0 flex-col">
          <h2 className="sr-only">{title}</h2>
          {description ? <p className="sr-only">{description}</p> : null}
          {children}
        </div>,
        outlet,
      )}
    </>
  );
}

interface FocusedContextRegistrationProps {
  ownerToken: number;
  context: LighthouseContextItem;
}

function FocusedContextRegistration({
  ownerToken,
  context,
}: FocusedContextRegistrationProps) {
  useMountEffect(() => {
    useLighthouseContextStore.getState().setFocusedContext(ownerToken, context);
    return () =>
      useLighthouseContextStore.getState().clearFocusedContext(ownerToken);
  });

  return null;
}
