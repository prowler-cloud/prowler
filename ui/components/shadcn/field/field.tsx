import { cn } from "@/lib/utils";

function Field({ className, ...props }: React.ComponentProps<"div">) {
  return (
    <div
      data-slot="field"
      className={cn("flex flex-col gap-1.5", className)}
      {...props}
    />
  );
}

function FieldLabel({ className, ...props }: React.ComponentProps<"label">) {
  return (
    <label
      data-slot="field-label"
      className={cn(
        "text-text-neutral-tertiary text-xs font-light tracking-tight",
        className,
      )}
      {...props}
    />
  );
}

function FieldError({ className, ...props }: React.ComponentProps<"p">) {
  return (
    <p
      data-slot="field-error"
      className={cn("text-text-error-primary max-w-full text-xs", className)}
      {...props}
    />
  );
}

export { Field, FieldError, FieldLabel };
