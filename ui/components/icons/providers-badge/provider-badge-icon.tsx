import {
  getProviderBadge,
  getProviderLabel,
} from "@/lib/providers/provider-display";
import { cn } from "@/lib/utils";

interface ProviderBadgeIconProps {
  providerKey: string;
  size: number;
  className?: string;
}

/**
 * Resolves a provider key to its dedicated badge icon. Providers without
 * one yet (e.g. newly onboarded backend-only providers that haven't had
 * artwork added) fall back to an initials chip instead of rendering
 * nothing, so new providers never show up as a blank square.
 */
export const ProviderBadgeIcon = ({
  providerKey,
  size,
  className,
}: ProviderBadgeIconProps) => {
  const Badge = getProviderBadge(providerKey);
  if (Badge) {
    return <Badge size={size} className={className} />;
  }

  const label = getProviderLabel(providerKey);
  const initials = label.slice(0, 2).toUpperCase();

  return (
    <span
      className={cn(
        "bg-default-300 text-default-700 dark:bg-default-100/40 dark:text-default-500 flex shrink-0 items-center justify-center rounded-[22%] font-mono leading-none font-bold",
        className,
      )}
      style={{ width: size, height: size, fontSize: Math.max(size * 0.4, 7) }}
      aria-hidden="true"
    >
      {initials}
    </span>
  );
};
