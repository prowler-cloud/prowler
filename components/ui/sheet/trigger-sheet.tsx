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
}

export function TriggerSheet({
  triggerComponent,
  title,
  description,
  children,
}: TriggerSheetProps) {
  return (
    <Sheet>
      <SheetTrigger>{triggerComponent}</SheetTrigger>
      <SheetContent className="max-w-[95vw] pt-10 md:max-w-[55vw]">
        <SheetHeader>
          <SheetTitle className="sr-only">{title}</SheetTitle>
          <SheetDescription className="sr-only">{description}</SheetDescription>
        </SheetHeader>
        {children}
      </SheetContent>
    </Sheet>
  );
}
