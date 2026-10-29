"use client";

import { Check } from "lucide-react";
import Link from "next/link";
import { type ReactNode, useState } from "react";

import {
  getRealtimeCredential,
  getRealtimeFrameworks,
  getRealtimePolicy,
  getRealtimeSetup,
} from "@/actions/realtime";
import { CostAnomalyForm } from "@/components/realtime/cost-anomaly-settings";
import { CredentialsForm } from "@/components/realtime/credentials-form";
import { LighthouseSetupLink } from "@/components/realtime/demo-context";
import { FeedSetupPanel } from "@/components/realtime/feed-setup-panel";
import { AlertsSection } from "@/components/realtime/notifications-section";
import {
  ProviderSelect,
  syncProviderToUrl,
} from "@/components/realtime/provider-select";
import { RealtimeSection } from "@/components/realtime/realtime-stat-card";
import {
  PanelEmpty,
  PanelFailure,
  PanelLoading,
} from "@/components/realtime/realtime-states";
import { EnforcementStep } from "@/components/realtime/setup/enforcement-step";
import { ReviewStep } from "@/components/realtime/setup/review-step";
import { useRealtimeResource } from "@/components/realtime/use-realtime-resource";
import { Alert, AlertDescription, AlertTitle } from "@/components/shadcn/alert";
import { Badge } from "@/components/shadcn/badge/badge";
import { Button } from "@/components/shadcn/button/button";
import { useAuth } from "@/hooks/use-auth";
import { REALTIME_PRODUCT_NAME_TEXT } from "@/lib/realtime/demo";
import { settingsHref } from "@/lib/realtime/display";
import {
  providerLabel,
  type RealtimeProviderOption,
  resolveProviderId,
} from "@/lib/realtime/providers";
import {
  canEnterStep,
  nextStepAfter,
  resumeStep,
  SETUP_STEP,
  SETUP_STEP_LABELS,
  SETUP_STEP_ORDER,
  type SetupStep,
  stepBefore,
  stepProgress,
} from "@/lib/realtime/setup";
import type { RealtimePolicy, RealtimeSetupPayload } from "@/types/realtime";

interface RealtimeSetupWizardProps {
  providers: RealtimeProviderOption[];
  initialProviderId?: string;
  /** Whether a connected Lighthouse AI configuration exists; undefined when unknown. */
  lighthouseConfigured?: boolean;
}

function Progress({
  current,
  setup,
  onSelect,
}: {
  current: SetupStep;
  setup: RealtimeSetupPayload | undefined;
  onSelect: (step: SetupStep) => void;
}) {
  return (
    <ol aria-label="Setup steps" className="flex flex-wrap gap-2">
      {SETUP_STEP_ORDER.map((step, index) => {
        const progress = stepProgress(step, setup);
        const enterable = canEnterStep(step, setup);
        const isCurrent = step === current;
        return (
          <li key={step}>
            <button
              type="button"
              disabled={!enterable}
              aria-current={isCurrent ? "step" : undefined}
              onClick={() => onSelect(step)}
              className={
                isCurrent
                  ? "border-button-tertiary bg-bg-neutral-secondary text-text-neutral-primary flex items-center gap-2 rounded-lg border px-3 py-1.5 text-sm font-medium"
                  : "border-border-neutral-secondary text-text-neutral-secondary hover:bg-bg-neutral-secondary flex items-center gap-2 rounded-lg border px-3 py-1.5 text-sm disabled:cursor-not-allowed disabled:opacity-50"
              }
            >
              <span className="text-text-neutral-tertiary text-xs tabular-nums">
                {index + 1}
              </span>
              {SETUP_STEP_LABELS[step]}
              {progress.done && step !== SETUP_STEP.ACCOUNT && (
                <>
                  <Check aria-hidden="true" className="size-3.5" />
                  <span className="sr-only">done</span>
                </>
              )}
              {!progress.required && (
                <span className="text-text-neutral-tertiary text-xs">
                  optional
                </span>
              )}
            </button>
          </li>
        );
      })}
    </ol>
  );
}

function StepFrame({
  step,
  setup,
  children,
}: {
  step: SetupStep;
  setup: RealtimeSetupPayload | undefined;
  children: ReactNode;
}) {
  const progress = stepProgress(step, setup);
  return (
    <section
      aria-labelledby="setup-step-title"
      className="flex max-w-4xl flex-col gap-5"
    >
      <div className="flex flex-wrap items-center gap-3">
        <h2
          id="setup-step-title"
          className="text-text-neutral-primary text-lg font-semibold"
        >
          Step {SETUP_STEP_ORDER.indexOf(step) + 1} of {SETUP_STEP_ORDER.length}
          : {SETUP_STEP_LABELS[step]}
        </h2>
        <Badge variant={progress.required ? "tag" : "outline"}>
          {progress.required ? "Required" : "Optional"}
        </Badge>
        {progress.done && step !== SETUP_STEP.ACCOUNT && (
          <Badge variant="success">Done</Badge>
        )}
      </div>
      {children}
    </section>
  );
}

function StepNav({
  step,
  setup,
  onGo,
  hint,
}: {
  step: SetupStep;
  setup: RealtimeSetupPayload | undefined;
  onGo: (step: SetupStep) => void;
  hint?: string;
}) {
  const previous = stepBefore(step);
  const next = nextStepAfter(step);
  const progress = stepProgress(step, setup);
  const blocked = progress.required && !progress.done;
  return (
    <div className="flex flex-wrap items-center gap-3">
      {previous && (
        <Button variant="outline" onClick={() => onGo(previous)}>
          Back
        </Button>
      )}
      {next && (
        <Button disabled={blocked} onClick={() => onGo(next)}>
          {progress.required || progress.done ? "Continue" : "Skip for now"}
        </Button>
      )}
      {blocked && hint && (
        <span className="text-text-neutral-tertiary text-xs">{hint}</span>
      )}
    </div>
  );
}

function SetupFlow({
  providers,
  initialProviderId,
  startAtAccount,
  lighthouseConfigured,
  canManage,
}: {
  providers: RealtimeProviderOption[];
  initialProviderId?: string;
  startAtAccount: boolean;
  lighthouseConfigured?: boolean;
  canManage: boolean;
}) {
  const [providerId, setProviderId] = useState(
    resolveProviderId(providers, initialProviderId) ?? "",
  );
  const [chosen, setChosen] = useState<SetupStep | null>(
    startAtAccount ? SETUP_STEP.ACCOUNT : null,
  );

  const setup = useRealtimeResource(
    () => getRealtimeSetup(providerId),
    `setup:${providerId}`,
  );
  const policy = useRealtimeResource(
    () => getRealtimePolicy(providerId),
    `policy:${providerId}`,
  );
  const credential = useRealtimeResource(
    () => getRealtimeCredential(providerId),
    `credential:${providerId}`,
  );
  const frameworks = useRealtimeResource(
    () => getRealtimeFrameworks(),
    "frameworks",
  );

  // A save changes what is done; read it again without blanking the page.
  const refreshSetup = async () => {
    const result = await getRealtimeSetup(providerId);
    if (result.ok) setup.setData(result.data);
  };

  const provider = providers.find((item) => item.id === providerId);
  const loading = setup.loading || policy.loading;
  const failure = setup.failure ?? policy.failure;
  const resumeAt = setup.data ? resumeStep(setup.data) : null;
  const current: SetupStep | null = chosen ?? resumeAt;

  const go = (step: SetupStep) => {
    if (canEnterStep(step, setup.data)) setChosen(step);
  };

  const saved = (next: RealtimePolicy, advanceTo?: SetupStep) => {
    policy.setData(next);
    void refreshSetup();
    if (advanceTo) setChosen(advanceTo);
  };

  const body = () => {
    if (loading) return <PanelLoading label="Loading your setup" />;
    if (failure) {
      return (
        <PanelFailure
          failure={failure}
          onRetry={() => {
            setup.reload();
            policy.reload();
          }}
          subject="your setup"
        />
      );
    }
    if (setup.data?.activated && !chosen) {
      return (
        <PanelEmpty
          title="Prowler Realtime is already on for this account"
          description="Change anything later in Configuration."
        >
          <div className="flex gap-2">
            <Button asChild>
              <Link
                href={`/realtime?provider=${encodeURIComponent(providerId)}`}
              >
                Open the dashboard
              </Link>
            </Button>
            <Button asChild variant="outline">
              <Link href={settingsHref(providerId)}>Configure</Link>
            </Button>
          </div>
        </PanelEmpty>
      );
    }
    if (!current) return null;
    const flow = setup.data;

    switch (current) {
      case SETUP_STEP.ACCOUNT:
        return (
          <StepFrame step={current} setup={flow}>
            <p className="text-text-neutral-secondary max-w-prose text-sm">
              Choose the AWS account to set up. Prowler Realtime reads its
              CloudTrail events and, only if you allow it, fixes it.
            </p>
            <ProviderSelect
              providers={providers}
              value={providerId}
              onChange={(value) => {
                setProviderId(value);
                syncProviderToUrl({ provider: value });
              }}
            />
            <div>
              <Button onClick={() => setChosen(resumeAt ?? SETUP_STEP.FEED)}>
                Continue
              </Button>
            </div>
          </StepFrame>
        );
      case SETUP_STEP.FEED:
        return (
          <StepFrame step={current} setup={flow}>
            <FeedSetupPanel
              key={providerId}
              providerId={providerId}
              canManage={canManage}
              onFeedChanged={() => void refreshSetup()}
            />
            <StepNav
              step={current}
              setup={flow}
              onGo={go}
              hint="Pick an event feed above to continue. CloudTrail lookup needs no setup in your account."
            />
          </StepFrame>
        );
      case SETUP_STEP.ENFORCEMENT:
        return (
          <StepFrame step={current} setup={flow}>
            <EnforcementStep
              key={`${providerId}:${policy.data?.id ?? "new"}`}
              providerId={providerId}
              policy={policy.data ?? null}
              frameworkCatalog={frameworks.data ?? []}
              lighthouseConfigured={lighthouseConfigured}
              onSaved={(next) => saved(next, SETUP_STEP.REMEDIATION)}
            />
            <StepNav step={current} setup={flow} onGo={go} />
          </StepFrame>
        );
      case SETUP_STEP.REMEDIATION:
        return (
          <StepFrame step={current} setup={flow}>
            {credential.loading ? (
              <PanelLoading label="Loading credentials" />
            ) : credential.failure ? (
              <PanelFailure
                failure={credential.failure}
                onRetry={credential.reload}
                subject="the credentials"
              />
            ) : (
              <CredentialsForm
                providerId={providerId}
                credential={credential.data ?? null}
                canManage={canManage}
                onChanged={(next) => {
                  credential.setData(next);
                  void refreshSetup();
                }}
              />
            )}
            <StepNav step={current} setup={flow} onGo={go} />
          </StepFrame>
        );
      case SETUP_STEP.ALERTS:
        return (
          <StepFrame step={current} setup={flow}>
            <AlertsSection
              key={policy.data?.id ?? "new"}
              providerId={providerId}
              policy={policy.data ?? null}
              canManage={canManage}
              onSaved={(next) => saved(next)}
            />
            <StepNav step={current} setup={flow} onGo={go} />
          </StepFrame>
        );
      case SETUP_STEP.COST:
        return (
          <StepFrame step={current} setup={flow}>
            <RealtimeSection
              title="Cost anomalies"
              description="Turn the cost signal on for this account and choose how big a jump counts as an anomaly."
            >
              <CostAnomalyForm
                key={policy.data?.id ?? "new"}
                providerId={providerId}
                policy={policy.data ?? null}
                canManage={canManage}
                onSaved={(next) => saved(next)}
              />
            </RealtimeSection>
            <StepNav step={current} setup={flow} onGo={go} />
          </StepFrame>
        );
      case SETUP_STEP.ACTIVATE:
        return (
          <StepFrame step={current} setup={flow}>
            {flow ? (
              <ReviewStep
                providerId={providerId}
                providerName={provider ? providerLabel(provider) : providerId}
                policy={policy.data ?? null}
                setup={flow}
                canManage={canManage}
              />
            ) : null}
            <StepNav step={current} setup={flow} onGo={go} />
          </StepFrame>
        );
    }
  };

  return (
    <div className="flex flex-col gap-6">
      <div className="flex flex-col gap-2">
        <p className="text-text-neutral-secondary max-w-prose text-sm">
          Set up {REALTIME_PRODUCT_NAME_TEXT}. Nothing runs until you activate
          it in the last step. Every choice is saved as you go, so you can leave
          and come back where you stopped.
        </p>
        <div className="flex flex-wrap items-center gap-x-4 gap-y-1">
          <LighthouseSetupLink className="text-text-neutral-tertiary text-xs" />
          <Link
            href="/realtime"
            className="text-button-tertiary text-xs underline underline-offset-4"
          >
            Back to the demo dashboard
          </Link>
        </div>
      </div>
      {current && (
        <Progress current={current} setup={setup.data} onSelect={go} />
      )}
      {body()}
    </div>
  );
}

/**
 * The resumable setup wizard. Gated like the dashboard: it needs an AWS
 * account and the permission to change settings; without either it explains
 * and the demo dashboard stays as it is.
 */
export function RealtimeSetupWizard({
  providers,
  initialProviderId,
  lighthouseConfigured,
}: RealtimeSetupWizardProps) {
  const { permissions } = useAuth();
  const canManage = permissions.manage_prowler_realtime === true;

  if (providers.length === 0) {
    return (
      <PanelEmpty
        title="Connect an AWS account first"
        description="Prowler Realtime Detection and Remediation works on AWS accounts, and you have none connected yet. Add an AWS provider, then come back here to set it up. Until then the dashboard shows demo data."
      >
        <Button asChild>
          <Link href="/providers">Go to Providers</Link>
        </Button>
      </PanelEmpty>
    );
  }

  if (!canManage) {
    return (
      <div className="flex max-w-3xl flex-col gap-4">
        <Alert variant="info">
          <AlertTitle>You cannot set this up</AlertTitle>
          <AlertDescription>
            <p>
              Setting up {REALTIME_PRODUCT_NAME_TEXT} needs the Manage Realtime
              permission. Ask an administrator, or keep exploring the demo
              dashboard.
            </p>
          </AlertDescription>
        </Alert>
        <div>
          <Button asChild variant="outline">
            <Link href="/realtime">Back to the dashboard</Link>
          </Button>
        </div>
      </div>
    );
  }

  return (
    <SetupFlow
      providers={providers}
      initialProviderId={initialProviderId}
      startAtAccount={!providers.some((item) => item.id === initialProviderId)}
      lighthouseConfigured={lighthouseConfigured}
      canManage={canManage}
    />
  );
}
