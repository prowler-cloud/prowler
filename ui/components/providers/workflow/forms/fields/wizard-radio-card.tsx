import { cn } from "@/lib/utils";

interface WizardRadioCardProps {
  name: string;
  value: string;
  checked: boolean;
  onChange: (value: string) => void;
  children: React.ReactNode;
  isInvalid?: boolean;
}

export const WizardRadioCard = ({
  name,
  value,
  checked,
  onChange,
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
      <input
        type="radio"
        name={name}
        value={value}
        checked={checked}
        onChange={() => onChange(value)}
        className="sr-only"
      />
      <div className="flex items-center">
        <span className="ml-2">{children}</span>
      </div>
      <span className="border-default flex h-4 w-4 items-center justify-center rounded-full border">
        {checked && <span className="bg-button-primary h-2 w-2 rounded-full" />}
      </span>
    </label>
  );
};
