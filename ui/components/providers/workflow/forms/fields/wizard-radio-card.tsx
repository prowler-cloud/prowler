"use client";

import { RadioGroupItem } from "@/components/shadcn/radio-group/radio-group";
import { cn } from "@/lib/utils";

interface WizardRadioCardProps {
  value: string;
  children: React.ReactNode;
  isInvalid?: boolean;
}

export const WizardRadioCard = ({
  value,
  children,
  isInvalid = false,
}: WizardRadioCardProps) => {
  return (
    <div
      className={cn(
        "group inline-flex w-full cursor-pointer items-center justify-between gap-4 rounded-lg border-2 p-4",
        "border-default hover:border-button-primary",
        "has-[[data-state=checked]]:border-button-primary",
        isInvalid && "border-bg-fail",
      )}
    >
      <label
        htmlFor={value}
        className="flex flex-1 cursor-pointer items-center"
      >
        <span className="ml-2">{children}</span>
      </label>
      <RadioGroupItem value={value} id={value} />
    </div>
  );
};
