"use client";

import { MenuIcon } from "lucide-react";
import Link from "next/link";
import { useRef, useState } from "react";

import { ProwlerBrand } from "@/components/icons";
import { Menu } from "@/components/layout/sidebar/menu";
import { Button } from "@/components/shadcn/button/button";
import {
  Sheet,
  SheetContent,
  SheetDescription,
  SheetHeader,
  SheetTitle,
  SheetTrigger,
} from "@/components/shadcn/sheet";

export function SheetMenu() {
  const [open, setOpen] = useState(false);
  const triggerRef = useRef<HTMLButtonElement>(null);

  const handleSelect = () => {
    setOpen(false);
    return triggerRef.current;
  };

  return (
    <Sheet open={open} onOpenChange={setOpen}>
      <SheetTrigger className="lg:hidden" asChild>
        <Button
          ref={triggerRef}
          aria-label="Open menu"
          className="h-8"
          variant="outline"
          size="icon"
        >
          <MenuIcon size={20} />
        </Button>
      </SheetTrigger>
      <SheetContent className="flex h-full flex-col px-3 sm:w-72" side="left">
        <SheetHeader>
          <SheetTitle className="sr-only">Sidebar</SheetTitle>
          <SheetDescription className="sr-only" />
          <Button
            className="flex items-center justify-center pt-1 pb-2"
            variant="link"
            asChild
          >
            <Link
              href="/"
              className="flex items-center justify-center"
              onClick={handleSelect}
            >
              <ProwlerBrand />
            </Link>
          </Button>
        </SheetHeader>
        <Menu isOpen onSelect={handleSelect} />
      </SheetContent>
    </Sheet>
  );
}
