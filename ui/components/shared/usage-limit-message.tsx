import { ToastAction } from "@/components/shadcn/toast";
import { USAGE_LIMIT_MESSAGE } from "@/lib/action-errors";
import { PRICING_URL } from "@/lib/external-urls";
import { cn } from "@/lib/utils";

interface UsageLimitMessageProps {
  className?: string;
}

const VIEW_PLANS_LABEL = "View plans";

/** Inline link to Prowler pricing, in a new tab, for copy that explains the refusal itself. */
export const ViewPlansLink = () => (
  <a
    href={PRICING_URL}
    target="_blank"
    rel="noopener noreferrer"
    className="underline"
  >
    {VIEW_PLANS_LABEL}
  </a>
);

// Over-limit (trial-expired) notice: the shared copy plus Prowler pricing.
export const UsageLimitMessage = ({ className }: UsageLimitMessageProps) => (
  <p className={cn("text-text-error-primary text-sm", className)}>
    {USAGE_LIMIT_MESSAGE} <ViewPlansLink />
  </p>
);

/** Toast action for a usage-limit refusal: Prowler pricing, in a new tab. */
export const usageLimitToastAction = () => (
  <ToastAction altText={VIEW_PLANS_LABEL} asChild>
    <a href={PRICING_URL} target="_blank" rel="noopener noreferrer">
      {VIEW_PLANS_LABEL}
    </a>
  </ToastAction>
);
