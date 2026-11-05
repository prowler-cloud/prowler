import { ProviderTypeIcon } from "@/components/icons/providers-badge/provider-type-icon";
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
