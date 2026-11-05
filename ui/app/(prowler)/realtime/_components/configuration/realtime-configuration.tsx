"use client";

import { usePathname, useRouter, useSearchParams } from "next/navigation";
import { useState } from "react";

import { REALTIME_PARAM } from "@/app/(prowler)/realtime/_lib/routes";
import {
  CONFIG_SECTION,
  type ConfigSection,
  isStepRequired,
  sectionAfter,
  stepState,
} from "@/app/(prowler)/realtime/_lib/setup";
import type {
  RealtimeCredential,
  RealtimeFeed,
  RealtimeFramework,
  RealtimeNotificationTargets,
  RealtimePolicy,
  RealtimeRemediation,
  RealtimeSetupPayload,
} from "@/app/(prowler)/realtime/_types";

import { ActivateCard } from "./activate-card";
import { AlertsSection } from "./alerts-section";
import { CostSection } from "./cost-section";
import { EnforcementSection } from "./enforcement-section";
import { FeedSection } from "./feed-section";
import { RemediationSection } from "./remediation-section";
import type { SectionBaseProps } from "./section-props";
import { SetupRail } from "./setup-rail";

export interface RealtimeConfigurationProps {
  providerId: string;
  accountLabel: string;
  canManage: boolean;
  policy: RealtimePolicy | null;
  feed: RealtimeFeed | null;
  credential: RealtimeCredential | null;
  setup: RealtimeSetupPayload | null;
  frameworks: RealtimeFramework[];
  targets: RealtimeNotificationTargets | null;
  remediations: RealtimeRemediation[];
  lighthouseConfigured: boolean;
  initialSection: ConfigSection | null;
}

/** Setup and settings in one page: a section per API setup step. */
export function RealtimeConfiguration({
  providerId,
  accountLabel,
  canManage,
  policy,
  feed,
  credential,
  setup,
  frameworks,
  targets,
  remediations,
  lighthouseConfigured,
  initialSection,
}: RealtimeConfigurationProps) {
  const router = useRouter();
  const pathname = usePathname();
  const searchParams = useSearchParams();
  // Local state: which section is open is the user's, the URL only seeds it.
  const [openSection, setOpenSection] = useState<ConfigSection | null>(
    initialSection,
  );

  const syncUrl = (section: ConfigSection | null) => {
    const params = new URLSearchParams(searchParams.toString());
    if (section) params.set(REALTIME_PARAM.SECTION, section);
    else params.delete(REALTIME_PARAM.SECTION);
    const query = params.toString();
    router.replace(query ? `${pathname}?${query}` : pathname, {
      scroll: false,
    });
  };

  const openAndReveal = (section: ConfigSection) => {
    if (section !== CONFIG_SECTION.ACTIVATE) setOpenSection(section);
    syncUrl(section);
    document
      .getElementById(section)
      ?.scrollIntoView({ behavior: "smooth", block: "start" });
  };

  const close = () => {
    setOpenSection(null);
    syncUrl(null);
  };

  const saved = (section: ConfigSection) => {
    const next = sectionAfter(section, setup);
    setOpenSection(next === CONFIG_SECTION.ACTIVATE ? null : next);
    syncUrl(next);
    router.refresh();
  };

  const sectionProps = (
    section: ConfigSection,
    number: number,
  ): SectionBaseProps => ({
    providerId,
    number,
    state: stepState(setup, section),
    required: setup ? isStepRequired(setup, section) : false,
    open: openSection === section,
    canManage,
    onOpen: () => openAndReveal(section),
    onClose: close,
    onSaved: () => saved(section),
  });

  return (
    <div className="flex flex-col gap-6">
      {!canManage && (
        <p className="text-text-neutral-tertiary text-sm">
          You can see this configuration, but your role needs the Manage
          Realtime permission to change it.
        </p>
      )}
      <div className="flex flex-col-reverse gap-6 lg:grid lg:grid-cols-[minmax(0,1fr)_18rem] lg:items-start">
        <div className="flex min-w-0 flex-col gap-4">
          <FeedSection feed={feed} {...sectionProps(CONFIG_SECTION.FEED, 1)} />
          <EnforcementSection
            policy={policy}
            frameworks={frameworks}
            lighthouseConfigured={lighthouseConfigured}
            {...sectionProps(CONFIG_SECTION.ENFORCEMENT, 2)}
          />
          <RemediationSection
            credential={credential}
            remediations={remediations}
            {...sectionProps(CONFIG_SECTION.REMEDIATION, 3)}
          />
          <AlertsSection
            policy={policy}
            targets={targets}
            {...sectionProps(CONFIG_SECTION.ALERTS, 4)}
          />
          <CostSection
            policy={policy}
            {...sectionProps(CONFIG_SECTION.COST, 5)}
          />
          <ActivateCard
            providerId={providerId}
            accountLabel={accountLabel}
            policy={policy}
            feed={feed}
            credential={credential}
            setup={setup}
            canManage={canManage}
            onOpenSection={openAndReveal}
            onSaved={() => router.refresh()}
          />
        </div>
        <div className="lg:sticky lg:top-6">
          <SetupRail setup={setup} onOpenSection={openAndReveal} />
        </div>
      </div>
    </div>
  );
}
