"use client";

import Link from "next/link";
import { useId, useState } from "react";

import { saveRealtimePolicy } from "@/actions/realtime";
import { FrameworkPicker } from "@/components/realtime/framework-picker";
import { RealtimeSection } from "@/components/realtime/realtime-stat-card";
import { ScopeTagsEditor } from "@/components/realtime/scope-tags-editor";
import { ToggleRow } from "@/components/realtime/toggle-row";
import { Alert, AlertDescription, AlertTitle } from "@/components/shadcn/alert";
import { Badge } from "@/components/shadcn/badge/badge";
import { Button } from "@/components/shadcn/button/button";
import { Field, FieldError, FieldLabel } from "@/components/shadcn/field/field";
import { Input } from "@/components/shadcn/input/input";
import { Modal } from "@/components/shadcn/modal";
import {
  RadioGroup,
  RadioGroupItem,
} from "@/components/shadcn/radio-group/radio-group";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/shadcn/select/select";
import { Textarea } from "@/components/shadcn/textarea/textarea";
import { useToast } from "@/components/shadcn/toast";
import {
  humanize,
  MODE_DESCRIPTIONS,
  policyChangesAccount,
} from "@/lib/realtime/display";
import {
  DEFAULT_REALTIME_POLICY,
  newScopeRow,
  policyFieldErrors,
  type ScopeRow,
  scopeRowsToTags,
  splitList,
} from "@/lib/realtime/policy-schema";
import {
  REALTIME_MIN_SEVERITY,
  REALTIME_MODE,
  type RealtimeFramework,
  type RealtimeMode,
  type RealtimePolicy,
  type RealtimePolicyInput,
} from "@/types/realtime";

interface PolicyFormProps {
  providerId: string;
  policy: RealtimePolicy | null;
  canManage: boolean;
  onSaved: (policy: RealtimePolicy) => void;
  /** The frameworks a policy can enforce; empty when the list could not be loaded. */
  frameworkCatalog?: RealtimeFramework[];
  /** Whether a connected Lighthouse AI configuration exists; undefined when unknown. */
  lighthouseConfigured?: boolean;
}

const sectionsEditedElsewhere = (
  policy: RealtimePolicy,
): Pick<
  RealtimePolicyInput,
  | "cost_anomaly_enabled"
  | "cost_anomaly_min_ratio"
  | "cost_anomaly_min_delta"
  | "notifications"
> => ({
  cost_anomaly_enabled: policy.cost_anomaly_enabled,
  cost_anomaly_min_ratio: policy.cost_anomaly_min_ratio,
  cost_anomaly_min_delta: policy.cost_anomaly_min_delta,
  notifications: policy.notifications,
});

const toRows = (tags: Record<string, string>): ScopeRow[] =>
  Object.entries(tags).map(([key, value]) => newScopeRow(key, value));

export function PolicyForm({
  providerId,
  policy,
  canManage,
  onSaved,
  frameworkCatalog = [],
  lighthouseConfigured,
}: PolicyFormProps) {
  const { toast } = useToast();
  const id = useId();

  const initial: RealtimePolicyInput = policy ?? DEFAULT_REALTIME_POLICY;
  const [draft, setDraft] = useState<RealtimePolicyInput>(initial);
  const [denyText, setDenyText] = useState(initial.deny_checks.join("\n"));
  const [regionsText, setRegionsText] = useState(
    initial.allow_regions.join(", "),
  );
  const [rows, setRows] = useState<ScopeRow[]>(() =>
    toRows(initial.scope_tags),
  );
  const [errors, setErrors] = useState<Record<string, string>>({});
  const [saving, setSaving] = useState(false);
  const [confirmLive, setConfirmLive] = useState(false);

  const disabled = !canManage || saving;
  const patch = (changes: Partial<RealtimePolicyInput>) =>
    setDraft((current) => ({ ...current, ...changes }));

  /** The policy the inputs describe, or the errors that stop it. */
  const collect = ():
    | { ok: true; policy: RealtimePolicyInput }
    | { ok: false; errors: Record<string, string> } => {
    const scope = scopeRowsToTags(rows);
    const candidate: RealtimePolicyInput = {
      ...draft,
      // The cost fields and the alerts are edited elsewhere (their own page and
      // section) and this save sends the whole policy: carry what is stored
      // now, not what this form loaded, so it never wipes a newer save.
      ...(policy ? sectionsEditedElsewhere(policy) : {}),
      deny_checks: splitList(denyText),
      allow_regions: splitList(regionsText),
      scope_tags: scope.tags,
    };
    const found = policyFieldErrors(candidate);
    if (scope.error) found.scope_tags = scope.error;
    return Object.keys(found).length
      ? { ok: false, errors: found }
      : { ok: true, policy: candidate };
  };

  const persist = async (candidate: RealtimePolicyInput) => {
    setSaving(true);
    const result = await saveRealtimePolicy({
      providerId,
      policyId: policy?.id,
      policy: candidate,
    }).finally(() => setSaving(false));
    setConfirmLive(false);
    if (result.ok) {
      setErrors({});
      onSaved(result.data);
      toast({ title: "Policy saved" });
    } else {
      setErrors(result.fieldErrors ?? {});
      toast({
        variant: "destructive",
        title:
          result.status === 403
            ? "You cannot change the policy"
            : "Could not save the policy",
        description:
          result.status === 403
            ? "Changing the policy needs the Manage Realtime permission."
            : result.error,
      });
    }
  };

  const submit = () => {
    const collected = collect();
    if (!collected.ok) {
      setErrors(collected.errors);
      return;
    }
    setErrors({});
    // Going live in the account is the one change that cannot be taken back
    // by pressing "undo" in the form, so it asks first.
    const wasLive = policy ? policyChangesAccount(policy) : false;
    if (policyChangesAccount(collected.policy) && !wasLive) {
      setConfirmLive(true);
      return;
    }
    void persist(collected.policy);
  };

  const liveWarning = draft.mode === REALTIME_MODE.AUTO && !draft.dry_run;

  return (
    <form
      className="flex flex-col gap-8"
      onSubmit={(event) => {
        event.preventDefault();
        submit();
      }}
    >
      {!canManage && (
        <Alert variant="info">
          <AlertTitle>Read only</AlertTitle>
          <AlertDescription>
            <p>
              Your role can see the policy but not change it. Changing it needs
              the Manage Realtime permission.
            </p>
          </AlertDescription>
        </Alert>
      )}

      <RealtimeSection title="Response">
        <ToggleRow
          id={`${id}-enabled`}
          label="Enable Prowler Realtime for this account"
          description="While disabled, Prowler Realtime does not react to events. Nothing in the account or your code is touched."
          checked={draft.enabled}
          disabled={disabled}
          onChange={(enabled) => patch({ enabled })}
        />

        <fieldset className="flex flex-col gap-3">
          <legend className="text-text-neutral-primary mb-1 text-sm font-medium">
            Mode
          </legend>
          <RadioGroup
            value={draft.mode}
            disabled={disabled}
            onValueChange={(mode) => patch({ mode: mode as RealtimeMode })}
          >
            {Object.values(REALTIME_MODE).map((mode) => (
              <div key={mode} className="flex items-start gap-3">
                <RadioGroupItem
                  id={`${id}-mode-${mode}`}
                  value={mode}
                  aria-describedby={`${id}-mode-${mode}-description`}
                  className="mt-0.5"
                />
                <div className="flex flex-col gap-0.5">
                  <label
                    htmlFor={`${id}-mode-${mode}`}
                    className="text-text-neutral-primary text-sm font-medium"
                  >
                    {MODE_DESCRIPTIONS[mode].label}
                  </label>
                  <p
                    id={`${id}-mode-${mode}-description`}
                    className="text-text-neutral-tertiary max-w-prose text-xs"
                  >
                    {MODE_DESCRIPTIONS[mode].consequence}
                  </p>
                </div>
              </div>
            ))}
          </RadioGroup>
        </fieldset>

        <ToggleRow
          id={`${id}-dry-run`}
          label="Dry run"
          description="Record what Prowler Realtime would change in the account without changing it. Applies to Fix automatically."
          checked={draft.dry_run}
          disabled={disabled}
          onChange={(dryRun) => patch({ dry_run: dryRun })}
        />
        {liveWarning && (
          <Alert variant="warning">
            <AlertTitle>Dry run is off</AlertTitle>
            <AlertDescription>
              <p>
                {draft.enabled
                  ? "Prowler Realtime will change resources in your AWS account as soon as it detects a matching risky change. Each change records how to undo it."
                  : "Once the policy is enabled, Prowler Realtime will change resources in your AWS account as soon as it detects a matching risky change."}
              </p>
            </AlertDescription>
          </Alert>
        )}
        {errors.dry_run && <FieldError>{errors.dry_run}</FieldError>}
        {errors.mode && <FieldError>{errors.mode}</FieldError>}
      </RealtimeSection>

      <RealtimeSection title="What it acts on">
        <Field className="max-w-xs">
          <FieldLabel htmlFor={`${id}-severity`}>Minimum severity</FieldLabel>
          <Select
            value={draft.min_severity}
            disabled={disabled}
            onValueChange={(value) =>
              patch({
                min_severity: value as RealtimePolicyInput["min_severity"],
              })
            }
          >
            <SelectTrigger id={`${id}-severity`} size="sm">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              {Object.values(REALTIME_MIN_SEVERITY).map((severity) => (
                <SelectItem key={severity} value={severity}>
                  {humanize(severity)} and above
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
          {errors.min_severity && (
            <FieldError>{errors.min_severity}</FieldError>
          )}
        </Field>

        <Field>
          <FieldLabel htmlFor={`${id}-deny`}>
            Never fix automatically (check ids)
          </FieldLabel>
          <Textarea
            id={`${id}-deny`}
            value={denyText}
            disabled={disabled}
            rows={3}
            font="mono"
            placeholder="rds_instance_no_public_access"
            aria-describedby={`${id}-deny-hint`}
            onChange={(event) => setDenyText(event.target.value)}
          />
          <p
            id={`${id}-deny-hint`}
            className="text-text-neutral-tertiary text-xs"
          >
            One check id per line or separated by commas. These fall back to a
            pull request.
          </p>
          {errors.deny_checks && <FieldError>{errors.deny_checks}</FieldError>}
        </Field>

        <Field>
          <FieldLabel htmlFor={`${id}-regions`}>Allowed regions</FieldLabel>
          <Input
            id={`${id}-regions`}
            value={regionsText}
            disabled={disabled}
            placeholder="eu-west-1, us-east-1"
            aria-describedby={`${id}-regions-hint`}
            onChange={(event) => setRegionsText(event.target.value)}
          />
          <p
            id={`${id}-regions-hint`}
            className="text-text-neutral-tertiary text-xs"
          >
            Prowler Realtime only acts in these regions. Empty means all
            regions.
          </p>
          {errors.allow_regions && (
            <FieldError>{errors.allow_regions}</FieldError>
          )}
        </Field>

        <FrameworkPicker
          catalog={frameworkCatalog}
          selected={draft.frameworks}
          disabled={disabled}
          error={errors.frameworks}
          onChange={(frameworks) => patch({ frameworks })}
        />

        <ScopeTagsEditor
          rows={rows}
          disabled={disabled}
          error={errors.scope_tags}
          onChange={setRows}
        />
      </RealtimeSection>

      <RealtimeSection
        title="Changes in code"
        description="Where Prowler Realtime proposes fixes to your infrastructure code."
      >
        <div className="grid grid-cols-1 gap-4 md:grid-cols-2">
          <Field>
            <FieldLabel htmlFor={`${id}-repo`}>GitHub repository</FieldLabel>
            <Input
              id={`${id}-repo`}
              value={draft.iac_repo}
              disabled={disabled}
              placeholder="owner/repo"
              aria-invalid={Boolean(errors.iac_repo)}
              onChange={(event) => patch({ iac_repo: event.target.value })}
            />
            {errors.iac_repo && <FieldError>{errors.iac_repo}</FieldError>}
          </Field>
          <Field>
            <FieldLabel htmlFor={`${id}-path`}>Terraform directory</FieldLabel>
            <Input
              id={`${id}-path`}
              value={draft.iac_path}
              disabled={disabled}
              placeholder="infra/terraform"
              aria-invalid={Boolean(errors.iac_path)}
              onChange={(event) => patch({ iac_path: event.target.value })}
            />
            {errors.iac_path && <FieldError>{errors.iac_path}</FieldError>}
          </Field>
        </div>
        <ToggleRow
          id={`${id}-open-pr`}
          label="Open pull requests"
          description="Open the pull request for you. Off, Prowler Realtime only prepares the branch. Needs a GitHub token below."
          checked={draft.open_pr}
          disabled={disabled}
          onChange={(openPr) => patch({ open_pr: openPr })}
        />
        {errors.open_pr && <FieldError>{errors.open_pr}</FieldError>}
        <div className="flex flex-col gap-2">
          <ToggleRow
            id={`${id}-lighthouse`}
            label="Let Lighthouse AI write the code change"
            description="For checks without a built-in patcher, Lighthouse AI writes the change using your configured LLM. The Terraform file and the finding are sent to that LLM provider. Pull requests are always reviewed by a person, and changes are checked by a security gate."
            checked={draft.use_lighthouse}
            disabled={disabled}
            onChange={(useLighthouse) =>
              patch({ use_lighthouse: useLighthouse })
            }
          />
          <div className="flex flex-wrap items-center gap-2 pl-14">
            {draft.use_lighthouse && lighthouseConfigured === false && (
              <Badge variant="warning">
                No Lighthouse AI configuration connected
              </Badge>
            )}
            <Link
              href="/lighthouse/settings"
              className="text-button-tertiary text-xs underline underline-offset-4"
            >
              Open Lighthouse AI settings
            </Link>
          </div>
          {errors.use_lighthouse && (
            <FieldError>{errors.use_lighthouse}</FieldError>
          )}
        </div>
      </RealtimeSection>

      {canManage && (
        <div className="flex items-center gap-3">
          <Button type="submit" disabled={saving}>
            {saving ? "Saving…" : "Save policy"}
          </Button>
          {Object.keys(errors).length > 0 && (
            <span role="alert" className="text-text-error-primary text-sm">
              Fix the highlighted fields and try again.
            </span>
          )}
        </div>
      )}

      <Modal
        open={confirmLive}
        onOpenChange={(open) => {
          if (!open && !saving) setConfirmLive(false);
        }}
        title="Let Prowler Realtime change your AWS account?"
        description="Mode is Fix automatically, dry run is off and the policy is enabled."
        size="lg"
      >
        <div className="flex flex-col gap-4">
          <p className="text-text-neutral-secondary text-sm">
            Prowler Realtime will apply supported fixes in this account when it
            detects a matching risky change, using the remediation role. Every
            change records the exact call that undoes it, and you can revert
            from the Remediation tab of the dashboard.
          </p>
          <div className="flex justify-end gap-2">
            <Button
              type="button"
              variant="outline"
              disabled={saving}
              onClick={() => setConfirmLive(false)}
            >
              Cancel
            </Button>
            <Button
              type="button"
              variant="destructive"
              disabled={saving}
              onClick={() => {
                const collected = collect();
                if (collected.ok) void persist(collected.policy);
              }}
            >
              {saving ? "Saving…" : "Enable live fixes"}
            </Button>
          </div>
        </div>
      </Modal>
    </form>
  );
}
