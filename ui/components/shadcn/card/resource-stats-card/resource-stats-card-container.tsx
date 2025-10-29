import { cva, type VariantProps } from "class-variance-authority";

import { cn } from "@/lib/utils";

const containerVariants = cva(
  [
    "flex",
    "rounded-[12px]",
    "border",
    "backdrop-blur-[46px]",
    "border-slate-300",
    "bg-[#F8FAFC80]",
    "dark:border-[rgba(38,38,38,0.70)]",
    "dark:bg-[rgba(23,23,23,0.50)]",
  ],
  {
    variants: {
      padding: {
        sm: "px-3 py-2",
        md: "px-[19px] py-[9px]",
        lg: "px-6 py-3",
        none: "p-0",
      },
    },
    defaultVariants: {
      padding: "md",
    },
  },
);

export interface ResourceStatsCardContainerProps
  extends React.HTMLAttributes<HTMLDivElement>,
    VariantProps<typeof containerVariants> {
  ref?: React.Ref<HTMLDivElement>;
}

export const ResourceStatsCardContainer = ({
  className,
  children,
  padding,
  ref,
  ...props
}: ResourceStatsCardContainerProps) => {
  return (
    <div
      ref={ref}
      className={cn(containerVariants({ padding }), className)}
      {...props}
    >
      {children}
    </div>
  );
};

ResourceStatsCardContainer.displayName = "ResourceStatsCardContainer";
