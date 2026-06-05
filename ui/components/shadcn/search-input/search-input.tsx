"use client";

import { cva, type VariantProps } from "class-variance-authority";
import { AnimatePresence, motion } from "framer-motion";
import { SearchIcon, XCircle } from "lucide-react";
import { ComponentProps, forwardRef } from "react";

import { cn } from "@/lib/utils";

const searchInputWrapperVariants = cva("relative flex items-center w-full", {
  variants: {
    size: {
      default: "",
      sm: "",
      lg: "",
    },
  },
  defaultVariants: {
    size: "default",
  },
});

const searchInputVariants = cva(
  "flex w-full rounded-lg border text-sm transition-[background-color,border-color,box-shadow,color] duration-250 ease-out outline-none motion-reduce:transition-none placeholder:text-text-neutral-tertiary disabled:cursor-not-allowed disabled:opacity-50",
  {
    variants: {
      variant: {
        default:
          "border-border-input-primary bg-bg-input-primary dark:bg-input/30 hover:bg-bg-neutral-secondary dark:hover:bg-input/50 focus:border-border-input-primary-press focus:ring-1 focus:ring-inset focus:ring-border-input-primary-press",
        ghost:
          "border-transparent bg-transparent hover:bg-bg-neutral-tertiary focus:bg-bg-neutral-tertiary",
      },
      size: {
        default: "h-10 pl-10 pr-10 py-3",
        sm: "h-8 pl-8 pr-8 py-2 text-xs",
        lg: "h-12 pl-12 pr-12 py-4",
      },
    },
    defaultVariants: {
      variant: "default",
      size: "default",
    },
  },
);

const iconSizeMap = {
  default: 16,
  sm: 14,
  lg: 20,
} as const;

const iconPositionMap = {
  default: "left-3",
  sm: "left-2.5",
  lg: "left-4",
} as const;

const clearButtonPositionMap = {
  default: "right-3",
  sm: "right-2.5",
  lg: "right-4",
} as const;

export interface SearchInputProps
  extends Omit<ComponentProps<"input">, "size">,
    VariantProps<typeof searchInputVariants> {
  onClear?: () => void;
}

const SearchInput = forwardRef<HTMLInputElement, SearchInputProps>(
  (
    {
      className,
      variant,
      size = "default",
      value,
      onClear,
      placeholder = "Search...",
      ...props
    },
    ref,
  ) => {
    const iconSize = iconSizeMap[size || "default"];
    const iconPosition = iconPositionMap[size || "default"];
    const clearButtonPosition = clearButtonPositionMap[size || "default"];
    const hasValue = value && String(value).length > 0;

    return (
      <div className={cn(searchInputWrapperVariants({ size }))}>
        <SearchIcon
          size={iconSize}
          className={cn(
            "text-text-neutral-tertiary pointer-events-none absolute transition-colors duration-250 ease-out motion-reduce:transition-none",
            iconPosition,
          )}
        />
        <input
          ref={ref}
          type="text"
          data-slot="search-input"
          value={value}
          placeholder={placeholder}
          className={cn(searchInputVariants({ variant, size, className }))}
          {...props}
        />
        <AnimatePresence initial={false}>
          {hasValue && onClear && (
            <motion.button
              key="clear-search"
              type="button"
              data-slot="search-input-clear"
              aria-label="Clear search"
              initial={{ opacity: 0, scale: 0.95 }}
              animate={{ opacity: 1, scale: 1 }}
              exit={{ opacity: 0, scale: 0.95 }}
              transition={{ duration: 0.25, ease: "easeOut" }}
              onClick={onClear}
              className={cn(
                "text-text-neutral-tertiary hover:text-text-neutral-primary absolute transition-colors duration-250 ease-out focus:outline-none motion-reduce:transition-none",
                clearButtonPosition,
              )}
            >
              <XCircle size={iconSize} />
            </motion.button>
          )}
        </AnimatePresence>
      </div>
    );
  },
);

SearchInput.displayName = "SearchInput";

export { SearchInput, searchInputVariants };
