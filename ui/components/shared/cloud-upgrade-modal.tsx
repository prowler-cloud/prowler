"use client";

import { Check, Cloud } from "lucide-react";

import { Button } from "@/components/shadcn/button/button";
import { Modal } from "@/components/shadcn/modal";
import {
  CLOUD_UPGRADE_CONTENT,
  CLOUD_UPGRADE_FEATURE,
  CLOUD_UPGRADE_FOOTER_NOTE,
  CLOUD_UPGRADE_SECONDARY_CTA,
  getCloudUpgradeCompareUrl,
  getCloudUpgradePrimaryUrl,
} from "@/lib/cloud-upgrade";
import { isCloud } from "@/lib/shared/env";
import { useCloudUpgradeStore } from "@/store";

import { CloudFeatureBadge } from "./cloud-feature-badge";

const allowInitialAutoFocus = () => {};

export const CloudUpgradeModal = () => {
  const activeFeature = useCloudUpgradeStore((state) => state.activeFeature);
  const closeCloudUpgrade = useCloudUpgradeStore(
    (state) => state.closeCloudUpgrade,
  );
  const returnFocusElement = useCloudUpgradeStore(
    (state) => state.returnFocusElement,
  );

  if (isCloud()) return null;

  const feature = activeFeature ?? CLOUD_UPGRADE_FEATURE.GENERAL;
  const content = CLOUD_UPGRADE_CONTENT[feature];

  return (
    <Modal
      open={activeFeature !== null}
      onOpenChange={(open) => !open && closeCloudUpgrade()}
      onOpenAutoFocus={allowInitialAutoFocus}
      onCloseAutoFocus={(event) => {
        event.preventDefault();
        returnFocusElement?.focus();
      }}
      title={content.title}
      description={content.description}
      size="lg"
    >
      <div className="space-y-6">
        <div className="flex items-center gap-3">
          <div className="bg-bg-neutral-tertiary text-text-neutral-primary flex size-10 items-center justify-center rounded-xl">
            <Cloud aria-hidden="true" className="size-5" />
          </div>
          <CloudFeatureBadge />
        </div>

        <ul className="space-y-3">
          {content.benefits.map((benefit) => (
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

        <div className="flex flex-col gap-3 sm:flex-row">
          <Button asChild className="flex-1">
            <a
              href={getCloudUpgradePrimaryUrl(feature)}
              target="_blank"
              rel="noopener noreferrer"
            >
              {content.primaryCta}
            </a>
          </Button>
          <Button asChild variant="outline" className="flex-1">
            <a
              href={getCloudUpgradeCompareUrl(feature)}
              target="_blank"
              rel="noopener noreferrer"
            >
              {CLOUD_UPGRADE_SECONDARY_CTA}
            </a>
          </Button>
        </div>

        <p className="text-text-neutral-tertiary text-center text-xs">
          {CLOUD_UPGRADE_FOOTER_NOTE}
        </p>
      </div>
    </Modal>
  );
};
