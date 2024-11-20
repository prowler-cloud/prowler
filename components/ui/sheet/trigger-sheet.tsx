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
      <SheetContent className="my-4 max-h-[calc(100vh-2rem)] max-w-[95vw] overflow-y-auto rounded-l-xl pt-10 dark:bg-prowler-theme-midnight md:my-8 md:max-h-[calc(100vh-4rem)] md:max-w-[55vw]">
        <SheetHeader>
          <SheetTitle className="sr-only">{title}</SheetTitle>
          <SheetDescription className="sr-only">{description}</SheetDescription>
        </SheetHeader>
        {children}
      </SheetContent>
    </Sheet>
  );
}
