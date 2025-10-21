import { cva, type VariantProps } from "class-variance-authority";

import { cn } from "@/lib/utils";

import { Card } from "../card";

const baseCardVariants = cva("", {
  variants: {
    variant: {
      default: "border-zinc-900 bg-stone-950",
    },
  },
  defaultVariants: {
    variant: "default",
  },
});

interface BaseCardProps
  extends React.ComponentProps<typeof Card>,
    VariantProps<typeof baseCardVariants> {}

const BaseCard = ({ className, variant, ...props }: BaseCardProps) => {
  return (
    <Card
      className={cn(
        baseCardVariants({ variant }),
        "gap-2 px-[18px] pt-3 pb-4",
        className,
      )}
      {...props}
    />
  );
};

export { BaseCard };
