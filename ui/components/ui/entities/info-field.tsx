interface InfoFieldProps {
  label: string;
  children: React.ReactNode;
  variant?: "default" | "simple";
}

export const InfoField = ({
  label,
  children,
  variant = "default",
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
    <div className="flex flex-col gap-1">
      <span className="text-xs font-bold text-gray-500 dark:text-prowler-theme-pale/70">
        {label}
      </span>
      <div className="rounded-lg bg-gray-50 px-3 py-2 text-small text-gray-900 dark:bg-prowler-blue-400 dark:text-prowler-theme-pale">
        {children}
      </div>
    </div>
  );
};
