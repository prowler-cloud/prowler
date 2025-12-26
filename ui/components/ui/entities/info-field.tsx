import { Tooltip } from "@heroui/tooltip";
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
  content="Download a ZIP file that includes the JSON (OCSF), CSV, and HTML scan reports, along with the compliance report."
>
  <div className="flex items-center gap-2">
    <InfoIcon className="text-primary mb-1" size={12} />
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
        <span className="text-text-neutral-tertiary text-xs font-bold">
          <span className="flex items-center gap-1">
            {label}:
            {tooltipContent && (
              <Tooltip className="text-xs" content={tooltipContent}>
                <div className="flex cursor-pointer items-center gap-2">
                  <InfoIcon className="text-bg-data-info mb-1" size={12} />
                </div>
              </Tooltip>
            )}
          </span>
        </span>
        <div className="text-text-neutral-primary text-sm">{children}</div>
      </div>
    );
  }

  return (
    <div className={clsx("flex flex-col gap-1", className)}>
      <span className="text-text-neutral-tertiary text-xs font-bold">
        <span className="flex items-center gap-1">
          {label}
          {tooltipContent && (
            <Tooltip className="text-xs" content={tooltipContent}>
              <div className="flex cursor-pointer items-center gap-2">
                <InfoIcon className="text-bg-data-info mb-1" size={12} />
              </div>
            </Tooltip>
          )}
        </span>
      </span>

      {variant === "simple" ? (
        <div className="text-text-neutral-primary text-sm break-all">
          {children}
        </div>
      ) : variant === "transparent" ? (
        <div className="text-text-neutral-primary text-sm">{children}</div>
      ) : (
        <div className="border-border-neutral-tertiary bg-bg-neutral-tertiary text-text-neutral-primary rounded-lg border px-3 py-2 text-sm">
          {children}
        </div>
      )}
    </div>
  );
};
