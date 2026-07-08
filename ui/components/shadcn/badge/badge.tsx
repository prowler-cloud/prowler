import { Slot } from "@radix-ui/react-slot";
import { cva, type VariantProps } from "class-variance-authority";
import { ComponentProps } from "react";

import { cn } from "@/lib/utils";

const badgeVariants = cva(
  "inline-flex items-center justify-center rounded-full border px-2 py-0.5 text-xs font-medium w-fit whitespace-nowrap shrink-0 [&>svg]:size-3 gap-1 [&>svg]:pointer-events-none focus-visible:border-ring focus-visible:ring-ring/50 focus-visible:ring-[3px] aria-invalid:ring-destructive/20 dark:aria-invalid:ring-destructive/40 aria-invalid:border-destructive transition-[color,box-shadow] overflow-hidden",
  {
    variants: {
      variant: {
        default:
          "border-transparent bg-button-primary text-black [a&]:hover:bg-button-primary/90",
        secondary:
          "border-transparent bg-violet-600 text-white dark:bg-violet-500 [a&]:hover:bg-violet-600/90 dark:[a&]:hover:bg-violet-500/90",
        destructive:
          "border-transparent bg-destructive text-white [a&]:hover:bg-destructive/90 focus-visible:ring-destructive/20 dark:focus-visible:ring-destructive/40 dark:bg-destructive/60",
        outline:
          "text-text-neutral-primary [a&]:hover:bg-accent [a&]:hover:text-accent-foreground",
        tag: "bg-bg-tag border-border-tag text-text-neutral-primary",
        success:
          "border-transparent bg-bg-pass-secondary text-text-success-primary",
        warning:
          "border-bg-warning/30 bg-bg-warning-secondary/20 text-text-warning-primary",
        error:
          "border-transparent bg-bg-fail-secondary text-text-error-primary",
        info: "border-transparent bg-bg-data-info/15 text-bg-data-info",
      },
    },
    defaultVariants: {
      variant: "default",
    },
  },
);

function Badge({
  className,
  variant,
  asChild = false,
  ...props
}: ComponentProps<"span"> &
  VariantProps<typeof badgeVariants> & { asChild?: boolean }) {
  const Comp = asChild ? Slot : "span";

  return (
    <Comp
      data-slot="badge"
      className={cn(badgeVariants({ variant }), className)}
      {...props}
    />
  );
}

export { Badge, badgeVariants };
