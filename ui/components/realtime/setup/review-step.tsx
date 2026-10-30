"use client";

import { useRouter } from "next/navigation";
import { type ReactNode, useState } from "react";

import {
  getRealtimeFrameworks,
  getRealtimeNotificationTargets,
  patchRealtimePolicy,
} from "@/actions/realtime";
import { useRealtimeResource } from "@/components/realtime/use-realtime-resource";
import { Alert, AlertDescription, AlertTitle } from "@/components/shadcn/alert";
import { Badge } from "@/components/shadcn/badge/badge";
import { Button } from "@/components/shadcn/button/button";
import { Modal } from "@/components/shadcn/modal";
import { useToast } from "@/components/shadcn/toast";
import {
  frameworkLabel,
  humanize,
  modeLabel,
  policyChangesAccount,
} from "@/lib/realtime/display";
import { notificationsSummary } from "@/lib/realtime/notifications";
import { stepProgress } from "@/lib/realtime/setup";
import {
  REALTIME_MODE,
  REALTIME_SETUP_STEP,
  type RealtimePolicy,
  type RealtimeSetupPayload,
} from "@/types/realtime";

interface ReviewStepProps {
  providerId: string;
  providerName: string;
  policy: RealtimePolicy | null;
  setup: RealtimeSetupPayload;
  canManage: boolean;
}

function Row({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div className="border-border-neutral-secondary flex flex-col gap-1 border-b py-3 last:border-b-0 sm:flex-row sm:gap-6">
      <dt className="text-text-neutral-secondary w-56 shrink-0 text-sm font-medium">
        {label}
      </dt>
      <dd className="text-text-neutral-primary flex flex-col gap-0.5 text-sm">
        {children}
      </dd>
    </div>
  );
}

/**
 * Step 7: every choice in one place. `enabled: true` is sent from here and
 * nowhere else; going live in the account asks once more.
 */
export function ReviewStep({
  providerId,
  providerName,
  policy,
  setup,
  canManage,
}: ReviewStepProps) {
  const router = useRouter();
  const { toast } = useToast();
  const [confirmLive, setConfirmLive] = useState(false);
  const [activating, setActivating] = useState(false);
  const [error, setError] = useState<string | undefined>();
  const frameworks = useRealtimeResource(
    () => getRealtimeFrameworks(),
    "frameworks",
  );
  const targets = useRealtimeResource(
    () => getRealtimeNotificationTargets(),
    "notification-targets",
  );

  const feed = stepProgress(REALTIME_SETUP_STEP.FEED, setup);
  const role = stepProgress(REALTIME_SETUP_STEP.REMEDIATION, setup);

  const activate = async () => {
    if (!policy) return;
    setActivating(true);
    setError(undefined);
    const result = await patchRealtimePolicy({
      providerId,
      policyId: policy.id,
      patch: { enabled: true },
    });
    setActivating(false);
    setConfirmLive(false);
    if (result.ok) {
      toast({
        title: "Prowler Realtime is on",
        description: "The dashboard now shows your account's own data.",
      });
      router.push(`/realtime?provider=${encodeURIComponent(providerId)}`);
    } else {
      setError(result.error);
      toast({
        variant: "destructive",
        title:
          result.status === 403
            ? "You cannot activate Prowler Realtime"
            : "Could not activate Prowler Realtime",
        description:
          result.status === 403
            ? "Activating needs the Manage Realtime permission."
            : result.error,
      });
    }
  };

  const onActivate = () => {
    if (!policy) return;
    if (policyChangesAccount({ ...policy, enabled: true })) {
      setConfirmLive(true);
      return;
    }
    void activate();
  };

  const alerts = policy
    ? notificationsSummary(policy.notifications, targets.data)
    : [];
  const scoped = policy ? Object.entries(policy.scope_tags) : [];

  return (
    <div className="flex flex-col gap-6">
      <p className="text-text-neutral-secondary max-w-prose text-sm">
        Check your choices. Nothing is switched on until you press Activate
        below; until then the dashboard keeps showing demo data.
      </p>

      <dl aria-label="Summary of your choices" className="flex flex-col">
        <Row label="AWS account">{providerName}</Row>
        <Row label="Event feed">
          <span>{feed.detail ?? (feed.done ? "Set up" : "Not set up")}</span>
        </Row>
        {policy ? (
          <>
            <Row label="Frameworks enforced">
              {policy.frameworks.length > 0 ? (
                <span className="flex flex-wrap gap-1.5">
                  {policy.frameworks.map((id) => (
                    <Badge key={id} variant="tag">
                      {frameworkLabel(id, frameworks.data)}
                    </Badge>
                  ))}
                </span>
              ) : (
                <span>Every check</span>
              )}
            </Row>
            <Row label="What Prowler does">
              <span>{modeLabel(policy.mode)}</span>
              {policy.mode === REALTIME_MODE.AUTO && (
                <span className="text-text-neutral-tertiary text-xs">
                  {policy.dry_run
                    ? "Dry run: records what it would change"
                    : "Live: changes the account"}
                </span>
              )}
              {policy.mode !== REALTIME_MODE.AUTO && (
                <span className="text-text-neutral-tertiary text-xs">
                  Dry run {policy.dry_run ? "on" : "off"}
                </span>
              )}
            </Row>
            <Row label="Minimum severity">
              {humanize(policy.min_severity)} and above
            </Row>
            <Row label="Scope">
              {scoped.length > 0
                ? scoped.map(([key, value]) => `${key}=${value}`).join(", ")
                : "Whole account"}
            </Row>
            <Row label="Lighthouse AI code fixes">
              {policy.use_lighthouse ? "On" : "Off"}
            </Row>
          </>
        ) : (
          <Row label="Enforcement">Not saved yet</Row>
        )}
        <Row label="Remediation permission">
          <span>
            {role.done
              ? (role.detail ?? "Role set")
              : "Not set: Prowler cannot change the account"}
          </span>
        </Row>
        <Row label="Alerts">
          {alerts.length > 0 ? (
            alerts.map((line) => <span key={line}>{line}</span>)
          ) : (
            <span>Off: nothing is sent</span>
          )}
        </Row>
        <Row label="Cost anomalies">
          {policy?.cost_anomaly_enabled
            ? `On (from ${policy.cost_anomaly_min_ratio}x and $${policy.cost_anomaly_min_delta})`
            : "Off"}
        </Row>
      </dl>

      {policy && policyChangesAccount({ ...policy, enabled: true }) && (
        <Alert variant="warning">
          <AlertTitle>This will change your AWS account</AlertTitle>
          <AlertDescription>
            <p>
              Mode is Fix automatically and dry run is off. Prowler Realtime
              will apply supported fixes as soon as it detects a matching risky
              change.
            </p>
          </AlertDescription>
        </Alert>
      )}

      {error && (
        <p role="alert" className="text-text-error-primary text-sm">
          {error}
        </p>
      )}

      {canManage ? (
        <div>
          <Button disabled={!policy || activating} onClick={onActivate}>
            {activating ? "Activating…" : "Activate Prowler Realtime"}
          </Button>
        </div>
      ) : (
        <p className="text-text-neutral-tertiary text-sm">
          Read only: activating needs the Manage Realtime permission.
        </p>
      )}

      <Modal
        open={confirmLive}
        onOpenChange={(open) => {
          if (!open && !activating) setConfirmLive(false);
        }}
        title="Let Prowler Realtime change your AWS account?"
        description="Mode is Fix automatically, dry run is off and you are about to activate."
        size="lg"
      >
        <div className="flex flex-col gap-4">
          <p className="text-text-neutral-secondary text-sm">
            Prowler Realtime will apply supported fixes in this account when it
            detects a matching risky change, using the remediation role. Most
            fixes record the exact call that undoes them, and you can revert
            those from the Remediation tab of the dashboard. Fixes marked
            &ldquo;Cannot be undone&rdquo;, such as restarting CloudTrail
            logging, cannot be reverted.
          </p>
          <div className="flex justify-end gap-2">
            <Button
              variant="outline"
              disabled={activating}
              onClick={() => setConfirmLive(false)}
            >
              Cancel
            </Button>
            <Button
              variant="destructive"
              disabled={activating}
              onClick={() => void activate()}
            >
              {activating ? "Activating…" : "Activate with live fixes"}
            </Button>
          </div>
        </div>
      </Modal>
    </div>
  );
}
