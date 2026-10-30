"use client";

import { Switch } from "@/components/shadcn/switch/switch";

/** A switch with its label and a one-line consequence under it. */
export function ToggleRow({
  id,
  label,
  description,
  checked,
  disabled,
  onChange,
}: {
  id: string;
  label: string;
  description: string;
  checked: boolean;
  disabled: boolean;
  onChange: (checked: boolean) => void;
}) {
  return (
    <div className="flex items-start gap-3">
      <Switch
        id={id}
        checked={checked}
        disabled={disabled}
        aria-describedby={`${id}-description`}
        onCheckedChange={onChange}
      />
      <div className="flex flex-col gap-0.5">
        <label
          htmlFor={id}
          className="text-text-neutral-primary text-sm font-medium"
        >
          {label}
        </label>
        <p
          id={`${id}-description`}
          className="text-text-neutral-tertiary max-w-prose text-xs"
        >
          {description}
        </p>
      </div>
    </div>
  );
}
