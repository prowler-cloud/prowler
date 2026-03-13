import {
  Sheet,
  SheetContent,
  SheetDescription,
  SheetHeader,
  SheetTitle,
  SheetTrigger,
} from "./sheet";

interface TriggerSheetProps {
  triggerComponent: React.ReactNode;
  title: string;
  description: string;
  children: React.ReactNode;
  open?: boolean;
  defaultOpen?: boolean;
  onOpenChange?: (open: boolean) => void;
}

export function TriggerSheet({
  triggerComponent,
  title,
  description,
  children,
  open,
  defaultOpen = false,
  onOpenChange,
}: TriggerSheetProps) {
  return (
    <Sheet open={open} defaultOpen={defaultOpen} onOpenChange={onOpenChange}>
      <SheetTrigger className="flex items-center gap-2">
        {triggerComponent}
      </SheetTrigger>
      <SheetContent className="my-4 max-h-[calc(100vh-2rem)] max-w-[95vw] overflow-y-auto pt-10 md:my-8 md:max-h-[calc(100vh-4rem)] md:max-w-[55vw]">
        <SheetHeader>
          <SheetTitle className="sr-only">{title}</SheetTitle>
          <SheetDescription className="sr-only">{description}</SheetDescription>
        </SheetHeader>
        {children}
      </SheetContent>
    </Sheet>
  );
}
