import Link from "next/link";

import { USAGE_LIMIT_MESSAGE } from "@/lib/action-errors";
import { BILLING_URL } from "@/lib/external-urls";
import { cn } from "@/lib/utils";

interface UsageLimitMessageProps {
  className?: string;
}

// Over-limit (trial-expired) notice shown in scan launch flows. Pairs the shared
// usage-limit copy with a link to Prowler Cloud billing.
export const UsageLimitMessage = ({ className }: UsageLimitMessageProps) => (
  <p className={cn("text-text-error-primary text-sm", className)}>
    {USAGE_LIMIT_MESSAGE}{" "}
    <Link
      href={BILLING_URL}
      target="_blank"
      rel="noopener noreferrer"
      className="underline"
    >
      Manage Billing
    </Link>
  </p>
);
