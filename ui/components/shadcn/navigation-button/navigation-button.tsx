import { Slot } from "@radix-ui/react-slot";
import { cva, type VariantProps } from "class-variance-authority";
import type { ComponentProps } from "react";

import { cn } from "@/lib/utils";

const navigationButtonVariants = cva(
  "focus-visible:ring-button-primary/50 flex min-w-0 items-center focus-visible:ring-2 focus-visible:outline-none",
  {
    variants: {
      variant: {
        item: "relative min-h-10 w-full justify-start gap-3 rounded-lg border px-3 py-2 text-left text-sm font-medium transition-all duration-200",
        subitem:
          "min-h-8 w-full justify-start gap-2 rounded-md px-3 py-1.5 text-left text-sm transition-colors",
        toggle:
          "h-8 flex-1 justify-center gap-1.5 rounded-lg border px-2 text-sm transition-all",
      },
      active: {
        true: "",
        false: "",
      },
      disabledState: {
        true: "pointer-events-none text-text-neutral-tertiary",
        false: "",
      },
    },
    compoundVariants: [
      {
        variant: "item",
        active: true,
        disabledState: false,
        class:
          "border-border-sidebar-active bg-bg-sidebar-active text-text-neutral-primary shadow-sidebar-active",
      },
      {
        variant: "item",
        active: false,
        disabledState: false,
        class:
          "text-text-neutral-secondary hover:border-border-sidebar-hover hover:bg-bg-sidebar-hover hover:text-text-neutral-primary border-transparent",
      },
      {
        variant: "subitem",
        active: true,
        disabledState: false,
        class:
          "bg-bg-sidebar-subitem-active text-text-neutral-primary font-medium",
      },
      {
        variant: "subitem",
        active: false,
        disabledState: false,
        class:
          "text-text-neutral-secondary hover:bg-bg-sidebar-hover hover:text-text-neutral-primary",
      },
      {
        variant: "toggle",
        active: true,
        disabledState: false,
        class:
          "border-border-sidebar-active bg-bg-sidebar-active text-text-neutral-primary shadow-sidebar-active",
      },
      {
        variant: "toggle",
        active: false,
        disabledState: false,
        class:
          "text-text-neutral-secondary hover:bg-bg-sidebar-hover hover:text-text-neutral-primary border-transparent",
      },
    ],
    defaultVariants: {
      variant: "item",
      active: false,
      disabledState: false,
    },
  },
);

interface NavigationButtonProps
  extends ComponentProps<"button">,
    VariantProps<typeof navigationButtonVariants> {
  asChild?: boolean;
}

function NavigationButton({
  active = false,
  asChild = false,
  className,
  disabledState = false,
  type,
  variant,
  ...props
}: NavigationButtonProps) {
  const Comp = asChild ? Slot : "button";

  return (
    <Comp
      data-slot="navigation-button"
      data-active={active}
      data-disabled={disabledState}
      type={asChild ? undefined : (type ?? "button")}
      className={cn(
        navigationButtonVariants({
          active,
          className,
          disabledState,
          variant,
        }),
      )}
      {...props}
    />
  );
}

export { NavigationButton };
