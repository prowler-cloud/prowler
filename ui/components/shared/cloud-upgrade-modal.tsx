"use client";

import { Check, Cloud } from "lucide-react";

import { Badge } from "@/components/shadcn/badge/badge";
import { Button } from "@/components/shadcn/button/button";
import { Modal } from "@/components/shadcn/modal";
import { useAuth } from "@/hooks/use-auth";
import {
  CLOUD_UPGRADE_CONTENT,
  CLOUD_UPGRADE_FOOTER_NOTE,
  CLOUD_UPGRADE_SECONDARY_CTA,
  getCloudUpgradeCompareUrl,
  getCloudUpgradePrimaryUrl,
  getPaidPlanUpgradeBillingHref,
  getPaidPlanUpgradeCompareUrl,
  isCloudUpgradeFeature,
  isPaidPlanUpgradeFeature,
  PAID_PLAN_UPGRADE_ADMIN_NOTE,
  PAID_PLAN_UPGRADE_BADGE,
  PAID_PLAN_UPGRADE_CONTENT,
} from "@/lib/cloud-upgrade";
import { isCloud } from "@/lib/shared/env";
import { useCloudUpgradeStore } from "@/store";
import type {
  CloudUpgradeFeature,
  PaidPlanUpgradeFeature,
} from "@/types/cloud-upgrade";

const allowInitialAutoFocus = () => {};

const CTA_CLASS_NAME =
  "h-auto min-h-9 w-full min-w-0 shrink whitespace-normal md:flex-1";

interface UpgradeModalCta {
  label: string;
  href: string;
  opensInNewTab: boolean;
}

interface UpgradeModalLayoutProps {
  open: boolean;
  onClose: () => void;
  returnFocusElement: HTMLElement | null;
  title: string;
  description: string;
  badge: string;
  benefits: readonly string[];
  primaryCta?: UpgradeModalCta;
  secondaryCta: UpgradeModalCta;
  footerNote?: string;
}

interface UpgradeModalLinkProps {
  cta: UpgradeModalCta;
  isSecondary?: boolean;
}

const UpgradeModalLink = ({ cta, isSecondary }: UpgradeModalLinkProps) => (
  <Button
    asChild
    variant={isSecondary ? "outline" : undefined}
    className={CTA_CLASS_NAME}
  >
    <a
      href={cta.href}
      title={cta.label}
      {...(cta.opensInNewTab && {
        target: "_blank",
        rel: "noopener noreferrer",
      })}
    >
      {cta.label}
    </a>
  </Button>
);

const UpgradeModalLayout = ({
  open,
  onClose,
  returnFocusElement,
  title,
  description,
  badge,
  benefits,
  primaryCta,
  secondaryCta,
  footerNote,
}: UpgradeModalLayoutProps) => (
  <Modal
    open={open}
    onOpenChange={(nextOpen) => !nextOpen && onClose()}
    onOpenAutoFocus={allowInitialAutoFocus}
    onCloseAutoFocus={(event) => {
      event.preventDefault();
      returnFocusElement?.focus();
    }}
    title={title}
    description={description}
    size="2xl"
  >
    <div className="min-w-0 space-y-6">
      <div className="flex items-center gap-3">
        <div className="bg-bg-neutral-tertiary text-text-neutral-primary flex size-10 items-center justify-center rounded-xl">
          <Cloud aria-hidden="true" className="size-5" />
        </div>
        <Badge variant="cloud">{badge}</Badge>
      </div>

      <ul className="space-y-3">
        {benefits.map((benefit) => (
          <li
            key={benefit}
            className="text-text-neutral-secondary flex items-start gap-3 text-sm"
          >
            <Check
              aria-hidden="true"
              className="text-text-success mt-0.5 size-4"
            />
            <span>{benefit}</span>
          </li>
        ))}
      </ul>

      <div className="flex flex-col gap-3 md:flex-row">
        {primaryCta && <UpgradeModalLink cta={primaryCta} />}
        <UpgradeModalLink cta={secondaryCta} isSecondary />
      </div>

      {footerNote && (
        <p className="text-text-neutral-tertiary text-center text-xs">
          {footerNote}
        </p>
      )}
    </div>
  </Modal>
);

interface UpgradeModalVariantProps {
  open: boolean;
  onClose: () => void;
  returnFocusElement: HTMLElement | null;
}

interface LocalServerUpgradeModalProps extends UpgradeModalVariantProps {
  feature: CloudUpgradeFeature;
}

const LocalServerUpgradeModal = ({
  feature,
  ...modalProps
}: LocalServerUpgradeModalProps) => {
  const content = CLOUD_UPGRADE_CONTENT[feature];

  return (
    <UpgradeModalLayout
      {...modalProps}
      title={content.title}
      description={content.description}
      badge="Available in Prowler Cloud"
      benefits={content.benefits}
      primaryCta={{
        label: content.primaryCta,
        href: getCloudUpgradePrimaryUrl(feature),
        opensInNewTab: true,
      }}
      secondaryCta={{
        label: CLOUD_UPGRADE_SECONDARY_CTA,
        href: getCloudUpgradeCompareUrl(feature),
        opensInNewTab: true,
      }}
      footerNote={CLOUD_UPGRADE_FOOTER_NOTE}
    />
  );
};

interface PaidPlanUpgradeModalProps extends UpgradeModalVariantProps {
  feature: PaidPlanUpgradeFeature;
}

const PaidPlanUpgradeModal = ({
  feature,
  ...modalProps
}: PaidPlanUpgradeModalProps) => {
  const { permissions } = useAuth();
  const content = PAID_PLAN_UPGRADE_CONTENT[feature];
  // The /billing route redirects users without billing access to /profile.
  const canManageBilling = permissions.manage_billing === true;

  return (
    <UpgradeModalLayout
      {...modalProps}
      title={content.title}
      description={content.description}
      badge={PAID_PLAN_UPGRADE_BADGE}
      benefits={content.benefits}
      primaryCta={
        canManageBilling
          ? {
              label: content.primaryCta,
              href: getPaidPlanUpgradeBillingHref(feature),
              opensInNewTab: false,
            }
          : undefined
      }
      secondaryCta={{
        label: CLOUD_UPGRADE_SECONDARY_CTA,
        href: getPaidPlanUpgradeCompareUrl(feature),
        opensInNewTab: true,
      }}
      footerNote={canManageBilling ? undefined : PAID_PLAN_UPGRADE_ADMIN_NOTE}
    />
  );
};

export const CloudUpgradeModal = () => {
  const activeFeature = useCloudUpgradeStore((state) => state.activeFeature);
  const retainedFeature = useCloudUpgradeStore(
    (state) => state.retainedFeature,
  );
  const closeCloudUpgrade = useCloudUpgradeStore(
    (state) => state.closeCloudUpgrade,
  );
  const returnFocusElement = useCloudUpgradeStore(
    (state) => state.returnFocusElement,
  );

  const feature = activeFeature ?? retainedFeature;
  const modalProps = {
    open: activeFeature !== null,
    onClose: closeCloudUpgrade,
    returnFocusElement,
  };

  // Cloud only upsells paid plans; Local Server only upsells Prowler Cloud.
  if (isCloud()) {
    return isPaidPlanUpgradeFeature(feature) ? (
      <PaidPlanUpgradeModal feature={feature} {...modalProps} />
    ) : null;
  }

  return isCloudUpgradeFeature(feature) ? (
    <LocalServerUpgradeModal feature={feature} {...modalProps} />
  ) : null;
};
