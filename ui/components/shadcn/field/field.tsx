import type { ReactNode } from "react";

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
        "text-text-neutral-tertiary text-xs font-medium",
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

interface LabeledFieldProps {
  label: string;
  children: ReactNode;
  className?: string;
}

function LabeledField({ label, children, className }: LabeledFieldProps) {
  return (
    <Field className={className}>
      <FieldLabel>{label}</FieldLabel>
      <span
        data-slot="field-value"
        className="text-text-neutral-primary text-sm"
      >
        {children}
      </span>
    </Field>
  );
}

export { Field, FieldError, FieldLabel, LabeledField };
