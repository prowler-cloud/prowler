"use client";

import Link from "next/link";

import { InfoIcon } from "@/components/icons/Icons";
import { Button, Card, CardContent } from "@/components/shadcn";
import { cn } from "@/lib/utils";

const NO_PROVIDERS_ADDED_ACTION = {
  BUTTON: "button",
  LINK: "link",
} as const;

interface NoProvidersAddedBaseProps {
  containerClassName?: string;
  // Tour anchor for the CTA; needed because this empty state replaces the table's AddProviderButton.
  ctaTourId?: string;
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

const renderCta = (props: NoProvidersAddedProps) => {
  if (props.action === NO_PROVIDERS_ADDED_ACTION.LINK) {
    return (
      <Button
        asChild
        aria-label="Open Add Provider modal"
        className="w-full max-w-xs justify-center"
        size="lg"
      >
        <Link href={props.href}>Get Started</Link>
      </Button>
    );
  }

  return (
    <Button
      aria-label="Open Add Provider modal"
      className="w-full max-w-xs justify-center"
      data-tour-id={props.ctaTourId}
      size="lg"
      onClick={props.onOpenWizard}
    >
      Get Started
    </Button>
  );
};

export const NoProvidersAdded = (props: NoProvidersAddedProps) => {
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

          {renderCta(props)}
        </CardContent>
      </Card>
    </div>
  );
};
