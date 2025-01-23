import clsx from "clsx";

interface InfoFieldProps {
  label: string;
  children: React.ReactNode;
  variant?: "default" | "simple";
  className?: string;
}

export const InfoField = ({
  label,
  children,
  variant = "default",
  className,
}: InfoFieldProps) => {
  if (variant === "simple") {
    return (
      <div className="flex flex-col gap-1">
        <span className="text-xs font-bold text-gray-500 dark:text-prowler-theme-pale/70">
          {label}
        </span>
        <div className="text-small text-gray-900 dark:text-prowler-theme-pale">
          {children}
        </div>
      </div>
    );
  }

  return (
    <div className={clsx("flex flex-col gap-1", className)}>
      <span className="text-xs font-bold text-gray-500 dark:text-prowler-theme-pale/70">
        {label}
      </span>
      <div className="rounded-lg bg-gray-50 px-3 py-2 text-small text-gray-900 dark:bg-slate-800 dark:text-prowler-theme-pale">
        {children}
      </div>
    </div>
  );
};
