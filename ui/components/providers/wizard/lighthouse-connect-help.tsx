"use client";

import { ExternalLink, Info } from "lucide-react";
import { useState } from "react";

import { LighthouseContextContributor } from "@/components/lighthouse/context-contributor";
import { usePanelSkillLaunch } from "@/components/lighthouse/use-panel-skill-launch";
import { Button } from "@/components/shadcn/button/button";
import {
  LighthouseCallout,
  LighthouseCalloutAction,
  LighthouseCalloutActions,
  LighthouseCalloutBody,
  LighthouseCalloutDescription,
  LighthouseCalloutIcon,
  LighthouseCalloutTitle,
} from "@/components/shadcn/lighthouse-callout";
import { getVisibleSidePanelTabs } from "@/components/side-panel/side-panel-tabs";
import { useMediaQuery } from "@/hooks/use-media-query";
import { useMountEffect } from "@/hooks/use-mount-effect";
import { buildProviderWizardContext } from "@/lib/lighthouse/context/contributions";
import { getSkillById } from "@/lib/lighthouse/skills/registry";
import {
  dispatchProviderFunnel,
  PROVIDER_FUNNEL_STEP,
} from "@/lib/provider-funnel/provider-funnel-events";
import { SIDE_PANEL_PUSH_MEDIA_QUERY } from "@/lib/ui-layout";
import { useProviderWizardStore } from "@/store/provider-wizard/store";
import { SIDE_PANEL_TAB, useSidePanelStore } from "@/store/side-panel";
import { LIGHTHOUSE_SKILL_ID } from "@/types/lighthouse-skills";
import type { ProviderWizardMode } from "@/types/provider-wizard";
import { getProviderDisplayName } from "@/types/providers";

import {
  buildProviderWizardHelpContext,
  resolveConnectionMethod,
} from "./lighthouse-connect-help.utils";

const CONNECTION_GUIDE_SKILL = getSkillById(
  LIGHTHOUSE_SKILL_ID.PROVIDER_CONNECTION_GUIDE,
);

interface LighthouseConnectHelpProps {
  docsLink: string;
  docsDestination: string;
  providerType: string | null;
  mode: ProviderWizardMode;
  // Stable step id for Lighthouse and analytics, and the label the stepper shows.
  stepName: string;
  stepLabel: string;
  isOrganizationsFlow: boolean;
}

// Wizard help: Lighthouse AI when it can sit beside the wizard, else the docs.
export function LighthouseConnectHelp({
  docsLink,
  docsDestination,
  providerType,
  mode,
  stepName,
  stepLabel,
  isOrganizationsFlow,
}: LighthouseConnectHelpProps) {
  const isLighthouseReady = useIsLighthouseReady();
  const isGuiding = useSidePanelStore(
    (state) => state.isOpen && state.selectedTab === SIDE_PANEL_TAB.AI_CHAT,
  );
  const launchPanelSkill = usePanelSkillLaunch();
  const providerUid = useProviderWizardStore((state) => state.providerUid);
  const via = useProviderWizardStore((state) => state.via);
  // Only the method leaves the AWS draft: its values may hold access keys.
  const awsDraftMethod = useProviderWizardStore(
    (state) => state.awsConnectDraft?.method,
  );

  if (!isLighthouseReady || !CONNECTION_GUIDE_SKILL) {
    return (
      <div className="text-muted-foreground flex flex-wrap items-center gap-2 text-sm">
        <Info className="size-4 shrink-0" />
        <span>For assistance connecting a Provider visit</span>
        <Button variant="link" size="link-sm" className="h-auto p-0" asChild>
          <a href={docsLink} target="_blank" rel="noopener noreferrer">
            <ExternalLink className="size-3.5 shrink-0" />
            <span>{`${docsDestination} Documentation`}</span>
          </a>
        </Button>
      </div>
    );
  }

  const wizardContext = {
    providerType,
    // The store keeps the last provider's account across opens; an organization has none.
    providerUid: isOrganizationsFlow ? null : providerUid,
    mode,
    stepName,
    stepLabel,
    connectionMethod: resolveConnectionMethod({
      isOrganizationsFlow,
      providerType,
      via,
      awsDraftMethod,
    }),
    docsUrl: docsLink,
  };

  const askLighthouse = () => {
    dispatchProviderFunnel({
      step: PROVIDER_FUNNEL_STEP.LIGHTHOUSE_HELP_OPENED,
      providerType,
      wizardStep: stepName,
    });
    launchPanelSkill(
      CONNECTION_GUIDE_SKILL,
      buildProviderWizardHelpContext(wizardContext),
    );
  };

  const providerName = providerType
    ? getProviderDisplayName(providerType)
    : null;
  const copy = getHelpCopy({ isGuiding, providerName });

  return (
    <LighthouseCallout
      aria-label="Help from Lighthouse AI"
      className="animate-in fade-in-0 slide-in-from-top-1 mt-2 duration-300"
    >
      <HelpShownSignal providerType={providerType} wizardStep={stepName} />
      <LighthouseCalloutIcon />
      <LighthouseCalloutBody>
        <LighthouseCalloutTitle>{copy.title}</LighthouseCalloutTitle>
        <LighthouseCalloutDescription>
          {copy.description}
        </LighthouseCalloutDescription>
      </LighthouseCalloutBody>
      <LighthouseCalloutActions>
        <Button variant="ghost" size="sm" asChild>
          <a href={docsLink} target="_blank" rel="noopener noreferrer">
            {`${docsDestination} docs`}
            <ExternalLink aria-hidden className="size-3.5" />
          </a>
        </Button>
        <LighthouseCalloutAction onClick={askLighthouse}>
          {copy.action}
        </LighthouseCalloutAction>
      </LighthouseCalloutActions>
      {/* Follow-ups typed in the panel carry the wizard's current state. */}
      <LighthouseContextContributor
        contributorId="provider-wizard"
        item={buildProviderWizardContext(wizardContext)}
      />
    </LighthouseCallout>
  );
}

interface HelpShownSignalProps {
  providerType: string | null;
  wizardStep: string;
}

// Mounted only while the callout renders: one exposure per wizard opening.
function HelpShownSignal({ providerType, wizardStep }: HelpShownSignalProps) {
  useMountEffect(() => {
    dispatchProviderFunnel({
      step: PROVIDER_FUNNEL_STEP.LIGHTHOUSE_HELP_SHOWN,
      providerType,
      wizardStep,
    });
  });
  return null;
}

interface HelpCopyInput {
  isGuiding: boolean;
  providerName: string | null;
}

function getHelpCopy({ isGuiding, providerName }: HelpCopyInput) {
  if (isGuiding) {
    return {
      title: "Lighthouse AI is guiding you",
      description: "Keep going here; its answers show up in the side panel.",
      action: "Ask about this step",
    };
  }
  return {
    title: providerName
      ? `Need a hand connecting ${providerName}?`
      : "Not sure how to connect your cloud?",
    description:
      "Lighthouse AI walks you through it with Prowler's docs, right beside this form.",
    action: "Ask Lighthouse AI",
  };
}

// Lighthouse AI can only help beside the wizard when the panel hosts the chat
// (cloud), the panel pushes instead of covering it, and an LLM is connected.
function useIsLighthouseReady(): boolean {
  const canHostChat = getVisibleSidePanelTabs().some(
    (tab) => tab.id === SIDE_PANEL_TAB.AI_CHAT,
  );
  const isPushViewport = useMediaQuery(SIDE_PANEL_PUSH_MEDIA_QUERY);
  // Local state needed: whether an LLM is connected is fetched once per open.
  const [hasConnectedLlm, setHasConnectedLlm] = useState(false);

  useMountEffect(() => {
    if (!canHostChat) return;
    let isMounted = true;
    // Lazy: the Lighthouse actions only load where the chat can exist (cloud).
    import("@/app/(prowler)/lighthouse/_actions")
      .then(({ getLighthouseV2Configurations }) =>
        getLighthouseV2Configurations(),
      )
      .then((result) => {
        if (!isMounted || "error" in result) return;
        setHasConnectedLlm(
          result.data.some((configuration) => configuration.connected),
        );
      })
      // Optional help: a failed check just leaves the docs link in place.
      .catch(() => {});
    return () => {
      isMounted = false;
    };
  });

  return canHostChat && isPushViewport && hasConnectedLlm;
}
