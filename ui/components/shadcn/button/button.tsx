import { Slot } from "@radix-ui/react-slot";
import { cva, type VariantProps } from "class-variance-authority";
import { ComponentProps } from "react";

import { cn } from "@/lib/utils";

const buttonVariants = cva(
  "inline-flex items-center justify-center gap-2 whitespace-nowrap rounded-md text-sm font-medium transition-all disabled:pointer-events-none disabled:bg-button-disabled disabled:text-text-neutral-tertiary outline-none focus-visible:ring-2 focus-visible:ring-offset-2 [&_svg]:pointer-events-none [&_svg:not([class*='size-'])]:size-4 shrink-0 [&_svg]:shrink-0",
  {
    variants: {
      variant: {
        default:
          "bg-button-primary text-black hover:bg-button-primary-hover active:bg-button-primary-press focus-visible:ring-button-primary/50",
        secondary:
          "bg-button-secondary text-white hover:bg-button-secondary/90 active:bg-button-secondary-press focus-visible:ring-button-secondary/50 dark:text-black",
        tertiary:
          "bg-button-tertiary text-white hover:bg-button-tertiary-hover active:bg-button-tertiary-active focus-visible:ring-button-tertiary/50",
        destructive:
          "bg-bg-fail text-white hover:bg-bg-fail/90 active:bg-bg-fail/80 focus-visible:ring-bg-fail/50",
        outline:
          "border border-border-neutral-secondary bg-bg-neutral-secondary hover:bg-bg-neutral-tertiary active:bg-border-neutral-tertiary text-text-neutral-primary focus-visible:ring-border-neutral-tertiary/50",
        ghost:
          "text-text-neutral-primary hover:bg-bg-neutral-tertiary active:bg-border-neutral-secondary focus-visible:ring-border-neutral-secondary/50",
        link: "text-button-tertiary underline-offset-4 hover:text-button-tertiary-hover disabled:bg-transparent",
        // Menu variant like secondary but more padding and the back is almost transparent
        menu: "backdrop-blur-xl bg-white/60 dark:bg-white/5 border border-white/80 dark:border-white/10 text-text-neutral-primary dark:text-white shadow-lg hover:bg-white/70 dark:hover:bg-white/10 hover:border-white/90 dark:hover:border-white/30 active:bg-white/80 dark:active:bg-white/15 active:scale-[0.98] focus-visible:ring-button-primary/50 transition-all duration-200",
        "menu-active":
          "backdrop-blur-xl bg-white/50 dark:bg-white/5 border border-black/[0.08] dark:border-white/10 text-text-neutral-primary dark:text-white shadow-sm hover:bg-white/60 dark:hover:bg-white/10 hover:border-black/[0.12] dark:hover:border-white/30 active:bg-white/70 dark:active:bg-white/15 active:scale-[0.98] focus-visible:ring-button-primary/50 transition-all duration-200",
        "menu-inactive":
          "text-text-neutral-primary border border-transparent hover:backdrop-blur-xl hover:bg-white/40 dark:hover:bg-white/5 hover:border-black/[0.08] dark:hover:border-white/10 hover:shadow-sm active:bg-white/50 dark:active:bg-white/15 active:scale-[0.98] focus-visible:ring-border-neutral-secondary/50 transition-all duration-200",
      },
      size: {
        default: "h-9 px-4 py-2 has-[>svg]:px-3",
        sm: "h-8 rounded-md gap-1.5 px-3 has-[>svg]:px-2.5",
        lg: "h-10 rounded-md px-6 has-[>svg]:px-4",
        xl: "h-12 rounded-md px-8 text-base has-[>svg]:px-6",
        icon: "size-9",
        "icon-sm": "size-8",
        "icon-lg": "size-10",
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
