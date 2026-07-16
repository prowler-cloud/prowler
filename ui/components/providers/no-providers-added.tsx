"use client";

import Link from "next/link";

import { InfoIcon } from "@/components/icons/Icons";
import { Button, Card, CardContent } from "@/components/shadcn";
import { cn } from "@/lib/utils";

const NO_PROVIDERS_ADDED_ACTION = {
  BUTTON: "button",
  LINK: "link",
} as const;

// "page" is the full-screen empty state (Providers page); "hint" is a compact
// horizontal banner that sits above other content (Scans page).
const NO_PROVIDERS_ADDED_VARIANT = {
  PAGE: "page",
  HINT: "hint",
} as const;

type NoProvidersAddedVariant =
  (typeof NO_PROVIDERS_ADDED_VARIANT)[keyof typeof NO_PROVIDERS_ADDED_VARIANT];

interface NoProvidersAddedBaseProps {
  containerClassName?: string;
  // Tour anchor for the CTA; needed because this empty state replaces the table's AddProviderButton.
  ctaTourId?: string;
  variant?: NoProvidersAddedVariant;
}

interface NoProvidersAddedButtonProps extends NoProvidersAddedBaseProps {
  action: typeof NO_PROVIDERS_ADDED_ACTION.BUTTON;
  onOpenWizard: () => void;
  href?: never;
}

interface NoProvidersAddedLinkProps extends NoProvidersAddedBaseProps {
  action: typeof NO_PROVIDERS_ADDED_ACTION.LINK;
  href: string;
  onOpenWizard?: never;
}

type NoProvidersAddedProps =
  | NoProvidersAddedButtonProps
  | NoProvidersAddedLinkProps;

const renderCta = (
  props: NoProvidersAddedProps,
  variant: NoProvidersAddedVariant,
) => {
  const isHint = variant === NO_PROVIDERS_ADDED_VARIANT.HINT;
  const className = isHint
    ? "w-full justify-center md:w-fit"
    : "w-full max-w-xs justify-center";
  const size = isHint ? undefined : "lg";

  if (props.action === NO_PROVIDERS_ADDED_ACTION.LINK) {
    return (
      <Button
        asChild
        aria-label="Open Add Provider modal"
        className={className}
        size={size}
      >
        <Link href={props.href}>Add a Provider</Link>
      </Button>
    );
  }

  return (
    <Button
      aria-label="Open Add Provider modal"
      className={className}
      data-tour-id={props.ctaTourId}
      size={size}
      onClick={props.onOpenWizard}
    >
      Add a Provider
    </Button>
  );
};

export const NoProvidersAdded = (props: NoProvidersAddedProps) => {
  const variant = props.variant ?? NO_PROVIDERS_ADDED_VARIANT.PAGE;

  // Compact horizontal hint, matching NoProvidersConnected so both provider
  // hints on the Scans page share one composition.
  if (variant === NO_PROVIDERS_ADDED_VARIANT.HINT) {
    return (
      <Card variant="base">
        <CardContent className="flex w-full flex-col items-start gap-6 md:flex-row md:items-center md:justify-between md:gap-8">
          <div className="flex flex-col gap-3">
            <div className="flex items-center justify-start gap-3">
              <InfoIcon className="h-6 w-6 text-gray-800 dark:text-white" />
              <h2 className="text-lg font-bold text-gray-800 dark:text-white">
                No Providers Configured
              </h2>
            </div>
            <p className="text-sm text-gray-600 dark:text-gray-300">
              No providers have been configured. Start by setting up a provider.
            </p>
          </div>
          <div className="w-full md:w-auto md:shrink-0">
            {renderCta(props, variant)}
          </div>
        </CardContent>
      </Card>
    );
  }

  return (
    <div
      role="region"
      aria-labelledby="no-providers-added-title"
      className={cn(
        "flex min-h-[calc(100dvh-10rem)] items-center justify-center",
        props.containerClassName,
      )}
    >
      <Card variant="base" className="mx-auto w-full max-w-3xl">
        <CardContent className="flex flex-col items-center gap-4 p-6 text-center sm:p-8">
          <div className="flex flex-col items-center gap-4">
            <InfoIcon className="h-10 w-10 text-gray-800 dark:text-white" />
            <h2
              id="no-providers-added-title"
              className="text-2xl font-bold text-gray-800 dark:text-white"
            >
              No Providers Configured
            </h2>
          </div>
          <div className="flex flex-col items-center gap-3">
            <p className="text-md leading-relaxed text-gray-600 dark:text-gray-300">
              No providers have been configured. Start by setting up a provider.
            </p>
          </div>

          {renderCta(props, variant)}
        </CardContent>
      </Card>
    </div>
  );
};
