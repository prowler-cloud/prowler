import { cva, type VariantProps } from "class-variance-authority";

import { cn } from "@/lib/utils";

export const CardVariant = {
  default: "default",
  fail: "fail",
  pass: "pass",
  warning: "warning",
  info: "info",
} as const;

export type CardVariant = (typeof CardVariant)[keyof typeof CardVariant];

const cardVariants = cva("flex flex-col gap-6 rounded-xl border", {
  variants: {
    variant: {
      default: "",
      base: "border-border-neutral-secondary bg-bg-neutral-secondary px-[18px] pt-3 pb-4",
      inner:
        "rounded-[12px] backdrop-blur-[46px] border-border-neutral-tertiary bg-bg-neutral-tertiary",
    },
    padding: {
      default: "",
      sm: "px-3 py-2",
      md: "px-4 py-3",
      lg: "px-5 py-4",
      none: "p-0",
    },
  },
  compoundVariants: [
    {
      variant: "inner",
      padding: "default",
      className: "px-4 py-3", // md padding by default for inner
    },
  ],
  defaultVariants: {
    variant: "default",
    padding: "default",
  },
});

interface CardProps
  extends React.ComponentProps<"div">,
    VariantProps<typeof cardVariants> {}

function Card({ className, variant, padding, ...props }: CardProps) {
  return (
    <div
      data-slot="card"
      className={cn(cardVariants({ variant, padding }), className)}
      {...props}
    />
  );
}

function CardHeader({ className, ...props }: React.ComponentProps<"div">) {
  return (
    <div
      data-slot="card-header"
      className={cn(
        "@container/card-header mb-6 grid auto-rows-min grid-rows-[auto_auto] items-start has-data-[slot=card-action]:grid-cols-[1fr_auto] [.border-b]:pb-6",
        className,
      )}
      {...props}
    />
  );
}

function CardTitle({ className, ...props }: React.ComponentProps<"div">) {
  return (
    <div
      data-slot="card-title"
      className={cn("mt-2 text-[18px] leading-none", className)}
      {...props}
    />
  );
}

function CardDescription({ className, ...props }: React.ComponentProps<"div">) {
  return (
    <div
      data-slot="card-description"
      className={cn("text-muted-foreground text-sm", className)}
      {...props}
    />
  );
}

function CardAction({ className, ...props }: React.ComponentProps<"div">) {
  return (
    <div
      data-slot="card-action"
      className={cn(
        "col-start-2 row-span-2 row-start-1 self-start justify-self-end",
        className,
      )}
      {...props}
    />
  );
}

function CardContent({ className, ...props }: React.ComponentProps<"div">) {
  return (
    <div data-slot="card-content" className={cn("", className)} {...props} />
  );
}

function CardFooter({ className, ...props }: React.ComponentProps<"div">) {
  return (
    <div
      data-slot="card-footer"
      className={cn("flex items-center px-6 [.border-t]:pt-6", className)}
      {...props}
    />
  );
}

export {
  Card,
  CardAction,
  CardContent,
  CardDescription,
  CardFooter,
  CardHeader,
  CardTitle,
  cardVariants,
};
export type { CardProps };
