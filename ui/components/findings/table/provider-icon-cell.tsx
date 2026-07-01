import {
  PROVIDER_TYPE_DATA,
  ProviderTypeIcon,
} from "@/components/icons/providers-badge/provider-type-icon";
import { cn } from "@/lib/utils";
import { ProviderType } from "@/types";

interface ProviderIconCellProps {
  provider: ProviderType;
  size?: number;
  className?: string;
}

export const ProviderIconCell = ({
  provider,
  size = 26,
  className = "size-8 rounded-md bg-white",
}: ProviderIconCellProps) => {
  // Unknown provider types (present in the data but missing from the shared
  // PROVIDER_TYPE_DATA map) render an explicit "?" rather than an empty icon.
  if (!(provider in PROVIDER_TYPE_DATA)) {
    return (
      <div className={cn("flex items-center justify-center", className)}>
        <span className="text-text-neutral-secondary text-xs">?</span>
      </div>
    );
  }

  return (
    <div
      className={cn(
        "flex items-center justify-center overflow-hidden",
        className,
      )}
    >
      <ProviderTypeIcon type={provider} size={size} />
    </div>
  );
};
