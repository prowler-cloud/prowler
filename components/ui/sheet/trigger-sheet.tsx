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
  defaultOpen?: boolean;
}

export function TriggerSheet({
  triggerComponent,
  title,
  description,
  children,
  defaultOpen = false,
}: TriggerSheetProps) {
  return (
    <Sheet defaultOpen={defaultOpen}>
      <SheetTrigger className="flex items-center gap-2">
        {triggerComponent}
      </SheetTrigger>
      <SheetContent className="max-w-[95vw] pt-10 md:max-w-[45vw]">
        <SheetHeader>
          <SheetTitle className="sr-only">{title}</SheetTitle>
          <SheetDescription className="sr-only">{description}</SheetDescription>
        </SheetHeader>
        {children}
      </SheetContent>
    </Sheet>
  );
}
