"use client";

import { cva, type VariantProps } from "class-variance-authority";
import { ComponentProps, forwardRef } from "react";

import { cn } from "@/lib/utils";

const inputVariants = cva(
  "flex w-full rounded-lg border text-sm transition-all outline-none file:border-0 file:bg-transparent file:text-sm file:font-medium disabled:cursor-not-allowed disabled:opacity-50",
  {
    variants: {
      variant: {
        default:
          "border-border-input-primary bg-bg-input-primary dark:bg-input/30 hover:bg-bg-neutral-secondary dark:hover:bg-input/50 focus:border-border-input-primary-press focus:ring-1 focus:ring-inset focus:ring-border-input-primary-press placeholder:text-text-neutral-tertiary",
        ghost:
          "border-transparent bg-transparent hover:bg-bg-neutral-tertiary focus:bg-bg-neutral-tertiary placeholder:text-text-neutral-tertiary",
      },
      inputSize: {
        default: "h-10 px-4 py-3",
        sm: "h-8 px-3 py-2 text-xs",
        lg: "h-12 px-5 py-4",
      },
    },
    defaultVariants: {
      variant: "default",
      inputSize: "default",
    },
  },
);

export interface InputProps
  extends Omit<ComponentProps<"input">, "size">,
    VariantProps<typeof inputVariants> {}

const Input = forwardRef<HTMLInputElement, InputProps>(
  ({ className, variant, inputSize, type = "text", ...props }, ref) => {
    return (
      <input
        ref={ref}
        type={type}
        data-slot="input"
        className={cn(inputVariants({ variant, inputSize, className }))}
        {...props}
      />
    );
  },
);

Input.displayName = "Input";

export { Input, inputVariants };
