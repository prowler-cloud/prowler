"use client";

import { RadioGroupItem } from "@/components/shadcn/radio-group/radio-group";
import { cn } from "@/lib/utils";

interface CustomRadioProps {
  description?: string;
  value?: string;
  children?: React.ReactNode;
}

export const CustomRadio = ({ value, children }: CustomRadioProps) => {
  return (
    <label
      className={cn(
        "inline-flex w-full max-w-full cursor-pointer flex-row-reverse items-center justify-between gap-4 rounded-lg border-2 p-4 hover:opacity-70 active:opacity-50",
        "border-border-input-primary hover:border-button-primary",
        "has-[[data-state=checked]]:border-button-primary",
      )}
    >
      <RadioGroupItem value={value || ""} />
      <span>{children}</span>
    </label>
  );
};
