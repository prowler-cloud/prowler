"use client";

import { CheckCircle2, Loader2, XCircleIcon } from "lucide-react";
import Link from "next/link";
import { useState } from "react";

import {
  confirmRecipient,
  unsubscribeRecipient,
} from "@/app/(prowler)/alerts/_actions";
import type { AlertPublicResponse } from "@/app/(prowler)/alerts/_types";
import { Button, Card, CardContent } from "@/components/shadcn";

// NOT FOR THE MVP: this UI supports public confirm/unsubscribe email links.
// The MVP assumes recipients belong to the tenant and are already confirmed.
export const ALERT_PUBLIC_ACTIONS = {
  CONFIRM: "confirm",
  UNSUBSCRIBE: "unsubscribe",
} as const;
export type AlertPublicActionKind =
  (typeof ALERT_PUBLIC_ACTIONS)[keyof typeof ALERT_PUBLIC_ACTIONS];

interface AlertPublicActionProps {
  action: AlertPublicActionKind;
  token: string | null;
  idleTitle: string;
  idleDescription: string;
  ctaLabel: string;
}

interface AlertPublicResultProps {
  variant: "success" | "error";
  title: string;
  description: string;
  primaryHref?: string;
  primaryLabel?: string;
  supportHref?: string;
}

const runners: Record<
  AlertPublicActionKind,
  (token: string) => Promise<AlertPublicResponse>
> = {
  confirm: confirmRecipient,
  unsubscribe: unsubscribeRecipient,
};

const AlertPublicResult = ({
  variant,
  title,
  description,
  primaryHref,
  primaryLabel,
  supportHref = "https://prowler.com/contact",
}: AlertPublicResultProps) => (
  <main className="flex min-h-screen items-center justify-center p-6">
    <Card variant="base" padding="lg" className="w-full max-w-md">
      <CardContent className="flex flex-col items-center gap-5 p-0 text-center">
        <div
          className={
            variant === "success"
              ? "bg-prowler-green-medium/10 flex h-14 w-14 items-center justify-center rounded-full"
              : "flex h-14 w-14 items-center justify-center rounded-full bg-rose-500/10"
          }
        >
          {variant === "success" ? (
            <CheckCircle2 className="text-prowler-green-medium h-7 w-7" />
          ) : (
            <XCircleIcon className="h-7 w-7 text-rose-500" />
          )}
        </div>
        <div className="flex flex-col gap-2">
          <h1 className="text-xl font-semibold text-gray-900 dark:text-gray-100">
            {title}
          </h1>
          <p className="max-w-sm text-sm text-gray-600 dark:text-gray-300">
            {description}
          </p>
        </div>
        <div className="flex flex-wrap items-center justify-center gap-2">
          {primaryHref && primaryLabel && (
            <Button asChild>
              <Link href={primaryHref}>{primaryLabel}</Link>
            </Button>
          )}
          <Button asChild variant="outline">
            <Link href={supportHref} target="_blank" rel="noopener noreferrer">
              Contact support
            </Link>
          </Button>
        </div>
      </CardContent>
    </Card>
  </main>
);

const renderResult = (
  action: AlertPublicActionKind,
  result: AlertPublicResponse,
): AlertPublicResultProps => {
  switch (result.state) {
    case "confirmed":
      return {
        variant: "success",
        title: "You're confirmed",
        description:
          "This address now receives Prowler Cloud alerts based on your team's alerts.",
        primaryHref: "https://prowler.com",
        primaryLabel: "Open Prowler Cloud",
      };
    case "already_confirmed":
      return {
        variant: "success",
        title: "Already confirmed",
        description:
          "Nothing to do, this address is already subscribed to Prowler Cloud alerts.",
      };
    case "unsubscribed":
      return {
        variant: "success",
        title: "You're unsubscribed",
        description:
          "We won't send you any more alert digests at this address. Pending notifications have been cancelled.",
      };
    case "already_unsubscribed":
      return {
        variant: "success",
        title: "Already unsubscribed",
        description:
          "This address is already unsubscribed from Prowler Cloud alerts.",
      };
    case "cannot_confirm":
      return {
        variant: "error",
        title: "This address can't be confirmed",
        description:
          "Earlier this address unsubscribed or stopped receiving deliveries. Ask your team to re-add it from the Prowler Cloud admin or contact support.",
      };
    case "superseded":
      return {
        variant: "error",
        title: "Link superseded",
        description:
          "A newer confirmation email has been issued for this address. Open the most recent invitation and use that link instead.",
      };
    case "missing_token":
      return {
        variant: "error",
        title: "Link is missing the token",
        description:
          "Open the original link from your email so the URL includes the token issued by Prowler Cloud.",
      };
    case "invalid_token":
      return {
        variant: "error",
        title: "Link is invalid or expired",
        description: `This ${action} link is no longer valid. Ask your team to resend the email.`,
      };
    case "not_found":
      return {
        variant: "error",
        title: "Recipient not found",
        description:
          "We couldn't locate the recipient referenced by this link. It may have been removed.",
      };
    case "network_error":
    default:
      return {
        variant: "error",
        title: "We couldn't reach the server",
        description:
          result.message ||
          "Try again in a few seconds. If this keeps happening, contact support.",
      };
  }
};

export const AlertPublicAction = ({
  action,
  token,
  idleTitle,
  idleDescription,
  ctaLabel,
}: AlertPublicActionProps) => {
  const [pending, setPending] = useState(false);
  const [result, setResult] = useState<AlertPublicResponse | null>(null);

  if (!token) {
    const view = renderResult(action, {
      state: "missing_token",
      message: "Token query parameter is missing.",
    });
    return <AlertPublicResult {...view} />;
  }

  if (result) {
    const view = renderResult(action, result);
    return <AlertPublicResult {...view} />;
  }

  const handleClick = async () => {
    setPending(true);
    const next = await runners[action](token);
    setPending(false);
    setResult(next);
  };

  return (
    <main className="flex min-h-screen items-center justify-center p-6">
      <Card variant="base" padding="lg" className="w-full max-w-md">
        <CardContent className="flex flex-col items-center gap-5 p-0 text-center">
          <div className="flex flex-col gap-2">
            <h1 className="text-xl font-semibold text-gray-900 dark:text-gray-100">
              {idleTitle}
            </h1>
            <p className="max-w-sm text-sm text-gray-600 dark:text-gray-300">
              {idleDescription}
            </p>
          </div>
          <Button onClick={handleClick} disabled={pending}>
            {pending ? (
              <>
                <Loader2 className="size-4 animate-spin" />
                Working...
              </>
            ) : (
              ctaLabel
            )}
          </Button>
        </CardContent>
      </Card>
    </main>
  );
};
