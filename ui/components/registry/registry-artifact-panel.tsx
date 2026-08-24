"use client";

import type { ReactNode } from "react";

import {
  Sheet,
  SheetContent,
  SheetHeader,
  SheetTitle,
} from "@/components/shadcn/sheet";

interface RegistryArtifactPanelProps {
  children: ReactNode;
  onClose: () => void;
  onCloseAutoFocus: (event: Event) => void;
  onOpenAutoFocus: (event: Event) => void;
  open: boolean;
}

export function RegistryArtifactPanel({
  children,
  onClose,
  onCloseAutoFocus,
  onOpenAutoFocus,
  open,
}: RegistryArtifactPanelProps) {
  return (
    <Sheet
      onOpenChange={(nextOpen) => {
        if (!nextOpen) onClose();
      }}
      open={open}
    >
      <SheetContent
        aria-describedby={undefined}
        className="flex w-full flex-col gap-0 p-0 sm:max-w-[480px]"
        onCloseAutoFocus={onCloseAutoFocus}
        onOpenAutoFocus={onOpenAutoFocus}
        side="right"
      >
        <SheetHeader className="sr-only">
          <SheetTitle>Artifact details</SheetTitle>
        </SheetHeader>
        {children}
      </SheetContent>
    </Sheet>
  );
}
