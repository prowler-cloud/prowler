import { cn } from "@/lib/utils";

function Section({ className, ...props }: React.ComponentProps<"section">) {
  return (
    <section
      data-slot="section"
      className={cn("flex flex-col gap-3", className)}
      {...props}
    />
  );
}

function SectionHeader({ className, ...props }: React.ComponentProps<"div">) {
  return (
    <div
      data-slot="section-header"
      className={cn("flex flex-col gap-1", className)}
      {...props}
    />
  );
}

function SectionTitle({ className, ...props }: React.ComponentProps<"h3">) {
  return (
    <h3
      data-slot="section-title"
      className={cn(
        "text-md text-text-neutral-primary leading-9 font-bold",
        className,
      )}
      {...props}
    />
  );
}

function SectionDescription({
  className,
  ...props
}: React.ComponentProps<"p">) {
  return (
    <p
      data-slot="section-description"
      className={cn("text-text-neutral-tertiary text-sm", className)}
      {...props}
    />
  );
}

function SectionContent({ className, ...props }: React.ComponentProps<"div">) {
  return (
    <div
      data-slot="section-content"
      className={cn("flex flex-col gap-3", className)}
      {...props}
    />
  );
}

export {
  Section,
  SectionContent,
  SectionDescription,
  SectionHeader,
  SectionTitle,
};
