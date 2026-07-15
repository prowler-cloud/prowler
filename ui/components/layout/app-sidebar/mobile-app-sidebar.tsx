"use client";

import { MenuIcon, X } from "lucide-react";
import { useRef, useState } from "react";

import { Button } from "@/components/shadcn/button/button";
import {
  Sheet,
  SheetClose,
  SheetContent,
  SheetDescription,
  SheetHeader,
  SheetTitle,
  SheetTrigger,
} from "@/components/shadcn/sheet";
import { cn } from "@/lib/utils";

import { AppSidebarContent } from "./app-sidebar-content";

export function MobileAppSidebar() {
  const [open, setOpen] = useState(false);
  const triggerRef = useRef<HTMLButtonElement>(null);

  const handleSelect = () => {
    setOpen(false);
    return triggerRef.current;
  };

  return (
    <Sheet open={open} onOpenChange={setOpen}>
      <SheetTrigger asChild>
        <Button
          ref={triggerRef}
          type="button"
          variant="bare"
          size="icon-sm"
          aria-label="Open menu"
          className={cn("lg:hidden", open && "invisible")}
        >
          <MenuIcon aria-hidden="true" className="size-5" />
        </Button>
      </SheetTrigger>
      <SheetContent side="left" variant="navigation" showCloseButton={false}>
        <SheetHeader className="sr-only">
          <SheetTitle>App sidebar</SheetTitle>
          <SheetDescription>Primary application navigation</SheetDescription>
        </SheetHeader>
        <SheetClose asChild>
          <Button
            type="button"
            variant="outline"
            size="icon-sm"
            aria-label="Close menu"
            className="fixed top-4 right-4 z-[60]"
          >
            <X aria-hidden="true" className="size-5" />
          </Button>
        </SheetClose>
        <AppSidebarContent onSelect={handleSelect} />
      </SheetContent>
    </Sheet>
  );
}
