import { Tooltip } from "@nextui-org/react";
import clsx from "clsx";
import { InfoIcon } from "lucide-react";

interface InfoFieldProps {
  label: string;
  children: React.ReactNode;
  variant?: "default" | "simple" | "transparent";
  className?: string;
  tooltipContent?: string;
  inline?: boolean;
}

<Tooltip
  className="text-xs"
  content="Download a ZIP file containing the JSON (OCSF), CSV, and HTML reports."
>
  <div className="flex items-center gap-2">
    <InfoIcon className="mb-1 text-primary" size={12} />
  </div>
</Tooltip>;

export const InfoField = ({
  label,
  children,
  variant = "default",
  tooltipContent,
  className,
  inline = false,
}: InfoFieldProps) => {
  if (inline) {
    return (
      <div className={clsx("flex items-center gap-2", className)}>
        <span className="text-xs font-bold text-gray-500 dark:text-prowler-theme-pale/70">
          <span className="flex items-center gap-1">
            {label}:
            {tooltipContent && (
              <Tooltip className="text-xs" content={tooltipContent}>
                <div className="flex cursor-pointer items-center gap-2">
                  <InfoIcon className="mb-1 text-primary" size={12} />
                </div>
              </Tooltip>
            )}
          </span>
        </span>
        <div className="text-sm">{children}</div>
      </div>
    );
  }

  return (
    <div className={clsx("flex flex-col gap-1", className)}>
      <span className="text-xs font-bold text-gray-500 dark:text-prowler-theme-pale/70">
        <span className="flex items-center gap-1">
          {label}
          {tooltipContent && (
            <Tooltip className="text-xs" content={tooltipContent}>
              <div className="flex cursor-pointer items-center gap-2">
                <InfoIcon className="mb-1 text-primary" size={12} />
              </div>
            </Tooltip>
          )}
        </span>
      </span>

      {variant === "simple" ? (
        <div className="text-small text-gray-900 dark:text-prowler-theme-pale">
          {children}
        </div>
      ) : variant === "transparent" ? (
        <div className="text-sm">{children}</div>
      ) : (
        <div className="rounded-lg bg-gray-50 px-3 py-2 text-sm text-gray-900 dark:bg-slate-800 dark:text-prowler-theme-pale">
          {children}
        </div>
      )}
    </div>
  );
};
