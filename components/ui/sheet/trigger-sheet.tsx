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
      <SheetContent className="w-[600px]">
        <SheetHeader>
          <SheetTitle>{title}</SheetTitle>
          <SheetDescription>{description}</SheetDescription>
        </SheetHeader>
        {children}
      </SheetContent>
    </Sheet>
  );
}
