import { cn } from "@/lib/utils";

interface RadioCardProps {
  icon: React.ComponentType<{ className?: string }>;
  title: string;
  onClick: () => void;
  disabled?: boolean;
  /** Optional trailing content (e.g. a CTA badge). */
  children?: React.ReactNode;
}

export function RadioCard({
  icon: Icon,
  title,
  onClick,
  disabled = false,
  children,
}: RadioCardProps) {
  return (
    <button
      type="button"
      onClick={onClick}
      disabled={disabled}
      className={cn(
        "flex min-h-[72px] w-full items-center gap-4 rounded-lg border px-3 py-2.5 text-left transition-colors",
        disabled
          ? "border-border-neutral-primary bg-bg-neutral-tertiary cursor-not-allowed"
          : "hover:border-primary border-border-neutral-primary bg-bg-neutral-tertiary cursor-pointer",
      )}
    >
      <div className="border-border-neutral-primary bg-bg-input-primary size-[18px] shrink-0 rounded-full border shadow-xs" />

      <div className="flex min-w-0 flex-1 items-center gap-1.5">
        <Icon
          className={cn(
            "size-[18px] shrink-0",
            disabled ? "text-text-neutral-tertiary" : "text-muted-foreground",
          )}
        />
        <span
          className={cn(
            "truncate text-sm leading-6",
            disabled ? "text-text-neutral-tertiary" : "text-foreground",
          )}
        >
          {title}
        </span>
      </div>

      {children}
    </button>
  );
}
