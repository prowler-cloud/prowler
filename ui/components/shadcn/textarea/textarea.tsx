"use client";

import { cva, type VariantProps } from "class-variance-authority";
import { ComponentProps, forwardRef } from "react";

import { cn } from "@/lib/utils";

const textareaVariants = cva(
  "flex w-full rounded-lg border text-sm transition-all outline-none resize-none disabled:cursor-not-allowed disabled:opacity-50",
  {
    variants: {
      variant: {
        default:
          "border-border-input-primary bg-bg-input-primary dark:bg-input/30 hover:bg-bg-neutral-secondary dark:hover:bg-input/50 focus:border-border-input-primary-press focus:ring-1 focus:ring-inset focus:ring-border-input-primary-press placeholder:text-text-neutral-tertiary",
        ghost:
          "border-transparent bg-transparent hover:bg-bg-neutral-tertiary focus:bg-bg-neutral-tertiary placeholder:text-text-neutral-tertiary",
      },
      textareaSize: {
        default: "min-h-16 px-4 py-3",
        sm: "min-h-12 px-3 py-2 text-xs",
        lg: "min-h-24 px-5 py-4",
      },
    },
    defaultVariants: {
      variant: "default",
      textareaSize: "default",
    },
  },
);

export interface TextareaProps
  extends Omit<ComponentProps<"textarea">, "size">,
    VariantProps<typeof textareaVariants> {}

const Textarea = forwardRef<HTMLTextAreaElement, TextareaProps>(
  ({ className, variant, textareaSize, ...props }, ref) => {
    return (
      <textarea
        ref={ref}
        data-slot="textarea"
        className={cn(textareaVariants({ variant, textareaSize, className }))}
        {...props}
      />
    );
  },
);

Textarea.displayName = "Textarea";

export { Textarea, textareaVariants };
