import { Slot } from "@radix-ui/react-slot";
import { cva, type VariantProps } from "class-variance-authority";
import type { ComponentProps } from "react";

import { cn } from "@/lib/utils";

const buttonVariants = cva(
  "inline-flex items-center justify-center gap-2 whitespace-nowrap rounded-[8px] text-sm font-medium transition-all disabled:pointer-events-none disabled:bg-button-disabled disabled:text-text-neutral-tertiary outline-none focus-visible:ring-2 focus-visible:ring-offset-2 [&_svg]:pointer-events-none [&_svg:not([class*='size-'])]:size-4 shrink-0 [&_svg]:shrink-0",
  {
    variants: {
      variant: {
        default:
          "border border-transparent bg-button-primary text-black font-semibold hover:bg-button-primary-hover active:bg-button-primary-press focus-visible:ring-button-primary/50",
        "primary-glow":
          "border border-border-sidebar-launch bg-button-primary text-black font-semibold shadow-sidebar-launch hover:bg-button-primary-hover hover:shadow-sidebar-launch-hover active:bg-button-primary-press focus-visible:ring-button-primary/50",
        secondary:
          "border border-transparent bg-button-secondary text-white hover:bg-button-secondary/90 active:bg-button-secondary-press focus-visible:ring-button-secondary/50 dark:text-black",
        tertiary:
          "border border-transparent bg-button-tertiary text-white hover:bg-button-tertiary-hover active:bg-button-tertiary-active focus-visible:ring-button-tertiary/50",
        destructive:
          "border border-transparent bg-bg-fail text-white hover:bg-bg-fail/90 active:bg-bg-fail/80 focus-visible:ring-bg-fail/50",
        outline:
          "border border-border-neutral-secondary bg-bg-neutral-secondary hover:bg-bg-neutral-tertiary active:bg-border-neutral-tertiary text-text-neutral-primary focus-visible:ring-border-neutral-tertiary/50",
        ghost:
          "border border-transparent text-text-neutral-primary hover:bg-bg-neutral-tertiary active:bg-border-neutral-secondary focus-visible:ring-border-neutral-secondary/50",
        link: "text-button-tertiary underline-offset-4 hover:text-button-tertiary-hover disabled:bg-transparent",
        // Chrome-free: no border/background, only the icon shows. Hover/active shift
        // the icon color instead of painting a box. Pair with an `icon*` size.
        bare: "border-0 bg-transparent p-0 text-text-neutral-secondary hover:text-text-neutral-primary active:text-text-neutral-primary focus-visible:ring-border-neutral-secondary/50 disabled:bg-transparent",
      },
      size: {
        default: "h-9 px-4 py-2 has-[>svg]:px-3",
        sm: "h-8 gap-1.5 px-3 has-[>svg]:px-2.5",
        lg: "h-10 px-6 has-[>svg]:px-4",
        xl: "h-12 px-8 text-base has-[>svg]:px-6",
        icon: "size-9",
        "icon-xs": "size-7",
        "icon-sm": "size-8",
        "icon-lg": "size-10",
        sidebar: "h-11 px-4 text-base has-[>svg]:px-3",
        "link-xs": "text-xs",
        "link-sm": "text-sm",
      },
    },
    defaultVariants: {
      variant: "default",
      size: "default",
    },
  },
);

function Button({
  className,
  variant,
  size,
  asChild = false,
  ...props
}: ComponentProps<"button"> &
  VariantProps<typeof buttonVariants> & {
    asChild?: boolean;
  }) {
  const Comp = asChild ? Slot : "button";

  return (
    <Comp
      data-slot="button"
      className={cn(buttonVariants({ variant, size, className }))}
      {...props}
    />
  );
}

export { Button, buttonVariants };
