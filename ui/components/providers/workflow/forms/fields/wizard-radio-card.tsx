"use client";

import { RadioGroupItem } from "@/components/shadcn/radio-group/radio-group";
import { cn } from "@/lib/utils";

interface WizardRadioCardProps {
  value: string;
  checked: boolean;
  children: React.ReactNode;
  isInvalid?: boolean;
}

export const WizardRadioCard = ({
  value,
  checked,
  children,
  isInvalid = false,
}: WizardRadioCardProps) => {
  return (
    <label
      className={cn(
        "group inline-flex w-full cursor-pointer items-center justify-between gap-4 rounded-lg border-2 p-4",
        checked
          ? "border-button-primary"
          : "border-default hover:border-button-primary",
        isInvalid && "border-bg-fail",
      )}
    >
      <div className="flex items-center">
        <span className="ml-2">{children}</span>
      </div>
      <RadioGroupItem value={value} />
    </label>
  );
};
