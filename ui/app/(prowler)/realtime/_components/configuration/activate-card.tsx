"use client";

import { CircleAlert, CircleCheck, Info } from "lucide-react";
import Link from "next/link";
import { useState } from "react";

import { patchRealtimePolicy } from "@/app/(prowler)/realtime/_actions";
import { ConfirmModal } from "@/app/(prowler)/realtime/_components/shared/confirm-modal";
import { policyChangesAccount } from "@/app/(prowler)/realtime/_lib/display";
import { realtimeHref } from "@/app/(prowler)/realtime/_lib/routes";
import {
  CONFIG_SECTION_LABELS,
  type ConfigSection,
  missingBeforeActivate,
  PREFLIGHT_LEVEL,
  type PreflightLevel,
  preflightChecks,
} from "@/app/(prowler)/realtime/_lib/setup";
import {
  REALTIME_MODE,
  type RealtimeCredential,
  type RealtimeFeed,
  type RealtimePolicy,
  type RealtimeSetupPayload,
} from "@/app/(prowler)/realtime/_types";
import { Badge, Button, Card, Switch } from "@/components/shadcn";
import { toast } from "@/components/shadcn/toast";
import { cn } from "@/lib/utils";

const PREFLIGHT_ICON: Record<PreflightLevel, typeof Info> = {
  [PREFLIGHT_LEVEL.OK]: CircleCheck,
  [PREFLIGHT_LEVEL.INFO]: Info,
  [PREFLIGHT_LEVEL.WARNING]: CircleAlert,
};

const PREFLIGHT_COLOR: Record<PreflightLevel, string> = {
  [PREFLIGHT_LEVEL.OK]: "text-text-success-primary",
  [PREFLIGHT_LEVEL.INFO]: "text-text-neutral-tertiary",
  [PREFLIGHT_LEVEL.WARNING]: "text-text-warning-primary",
};

const CONFIRM = {
  NONE: "none",
  LIVE: "live",
  PAUSE: "pause",
} as const;
type Confirm = (typeof CONFIRM)[keyof typeof CONFIRM];

interface ActivateCardProps {
  providerId: string;
  accountLabel: string;
  policy: RealtimePolicy | null;
  feed: RealtimeFeed | null;
  credential: RealtimeCredential | null;
  setup: RealtimeSetupPayload | null;
  canManage: boolean;
  onOpenSection: (section: ConfigSection) => void;
  onSaved: () => void;
}

export function ActivateCard({
  providerId,
  accountLabel,
  policy,
  feed,
  credential,
  setup,
  canManage,
  onOpenSection,
  onSaved,
}: ActivateCardProps) {
  const [confirm, setConfirm] = useState<Confirm>(CONFIRM.NONE);
  const [pending, setPending] = useState(false);
  const active = Boolean(policy?.enabled);
  const missing = missingBeforeActivate(setup);
  const checks = preflightChecks({ policy, feed, credential });
  const canActivate = canManage && Boolean(policy) && missing.length === 0;
  const dryRunAuto = policy?.mode === REALTIME_MODE.AUTO && policy.dry_run;

  const setEnabled = async (enabled: boolean) => {
    if (!policy) return;
    setPending(true);
    const result = await patchRealtimePolicy({
      providerId,
      policyId: policy.id,
      patch: { enabled },
    });
    setPending(false);
    if (!result.ok) {
      toast({
        variant: "destructive",
        title: enabled ? "Realtime not activated" : "Realtime not paused",
        description: result.error,
      });
      return;
    }
    setConfirm(CONFIRM.NONE);
    toast({ title: enabled ? "Realtime is active" : "Realtime is paused" });
    onSaved();
  };

  const requestActivate = () => {
    if (policy && policyChangesAccount({ ...policy, enabled: true })) {
      setConfirm(CONFIRM.LIVE);
      return;
    }
    void setEnabled(true);
  };

  return (
    <Card variant="base" id="activate" className="scroll-mt-24 gap-4">
      {active ? (
        <div className="flex flex-wrap items-center gap-4">
          <div className="flex min-w-0 flex-1 flex-col gap-0.5">
            <h2 className="text-text-neutral-primary text-sm font-semibold">
              Realtime is watching {accountLabel}
            </h2>
            <p className="text-text-neutral-tertiary text-xs">
              Pausing stops new detections and responses. History stays on the
              dashboard.
            </p>
          </div>
          <Badge variant="success">Active</Badge>
          <Switch
            aria-label="Realtime active"
            checked
            disabled={!canManage || pending}
            onCheckedChange={(checked) => {
              if (!checked) setConfirm(CONFIRM.PAUSE);
            }}
          />
          <Button variant="outline" size="sm" asChild>
            <Link href={realtimeHref(providerId)}>Open the dashboard</Link>
          </Button>
        </div>
      ) : (
        <>
          <div className="flex flex-col gap-0.5">
            <h2 className="text-text-neutral-primary text-sm font-semibold">
              {policy ? "Activate Realtime" : "Activate"}
            </h2>
            <p className="text-text-neutral-tertiary text-xs">
              Prowler starts watching {accountLabel} as soon as you activate it.
            </p>
          </div>
          <ul className="flex flex-col gap-2" aria-label="Before you activate">
            {checks.map((check) => {
              const Icon = PREFLIGHT_ICON[check.level];
              return (
                <li key={check.id} className="flex items-start gap-2 text-sm">
                  <Icon
                    aria-hidden
                    className={cn(
                      "mt-0.5 size-4 shrink-0",
                      PREFLIGHT_COLOR[check.level],
                    )}
                  />
                  <span className="text-text-neutral-secondary">
                    {check.message}{" "}
                    {check.section && check.level !== PREFLIGHT_LEVEL.OK && (
                      <Button
                        variant="link"
                        size="link-sm"
                        onClick={() =>
                          onOpenSection(check.section as ConfigSection)
                        }
                      >
                        Review {CONFIG_SECTION_LABELS[check.section]}
                      </Button>
                    )}
                  </span>
                </li>
              );
            })}
          </ul>
          <div className="flex flex-wrap items-center gap-3">
            <Button
              disabled={!canActivate || pending}
              onClick={requestActivate}
            >
              {dryRunAuto ? "Activate in dry run" : "Activate"}
            </Button>
            {missing.length > 0 && (
              <span className="text-text-neutral-tertiary text-xs">
                Finish first:{" "}
                {missing.map((id) => CONFIG_SECTION_LABELS[id]).join(", ")}.
              </span>
            )}
          </div>
        </>
      )}

      <ConfirmModal
        open={confirm === CONFIRM.LIVE}
        onOpenChange={(open) => !open && setConfirm(CONFIRM.NONE)}
        title="Let Prowler change your AWS account?"
        description="Dry run is off: supported fixes are applied to the account as soon as a check fails. Each fix records how to undo it."
        confirmLabel="Activate with live fixes"
        pending={pending}
        onConfirm={() => setEnabled(true)}
      />
      <ConfirmModal
        open={confirm === CONFIRM.PAUSE}
        onOpenChange={(open) => !open && setConfirm(CONFIRM.NONE)}
        title="Pause Realtime?"
        description="Prowler stops creating detections and responses for this account until you activate it again."
        confirmLabel="Pause"
        destructive
        pending={pending}
        onConfirm={() => setEnabled(false)}
      />
    </Card>
  );
}
