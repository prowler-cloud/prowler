"use client";

import Link from "next/link";
import { useId, useState } from "react";

import { patchRealtimePolicy, saveRealtimePolicy } from "@/actions/realtime";
import { FrameworkPicker } from "@/components/realtime/framework-picker";
import { ScopeTagsEditor } from "@/components/realtime/scope-tags-editor";
import { ToggleRow } from "@/components/realtime/toggle-row";
import { Alert, AlertDescription, AlertTitle } from "@/components/shadcn/alert";
import { Badge } from "@/components/shadcn/badge/badge";
import { Button } from "@/components/shadcn/button/button";
import { Field, FieldError, FieldLabel } from "@/components/shadcn/field/field";
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
import { useToast } from "@/components/shadcn/toast";
import { humanize, MODE_DESCRIPTIONS } from "@/lib/realtime/display";
import {
  newScopeRow,
  policyFieldErrors,
  type ScopeRow,
  scopeRowsToTags,
} from "@/lib/realtime/policy-schema";
import { WIZARD_DEFAULT_POLICY } from "@/lib/realtime/setup";
import {
  REALTIME_MIN_SEVERITY,
  REALTIME_MODE,
  type RealtimeFramework,
  type RealtimeMode,
  type RealtimePolicy,
  type RealtimePolicyInput,
} from "@/types/realtime";

interface EnforcementStepProps {
  providerId: string;
  policy: RealtimePolicy | null;
  frameworkCatalog: RealtimeFramework[];
  lighthouseConfigured?: boolean;
  onSaved: (policy: RealtimePolicy) => void;
}

type EnforcementPatch = Pick<
  RealtimePolicyInput,
  | "enabled"
  | "mode"
  | "dry_run"
  | "min_severity"
  | "frameworks"
  | "scope_tags"
  | "use_lighthouse"
>;

/**
 * Step 3: what Prowler Realtime enforces and how. Saves with `enabled: false`
 * (creating the policy the first time), so nothing runs yet.
 */
export function EnforcementStep({
  providerId,
  policy,
  frameworkCatalog,
  lighthouseConfigured,
  onSaved,
}: EnforcementStepProps) {
  const { toast } = useToast();
  const id = useId();
  const initial = policy ?? WIZARD_DEFAULT_POLICY;
  const [frameworks, setFrameworks] = useState(initial.frameworks);
  const [mode, setMode] = useState<RealtimeMode>(initial.mode);
  const [dryRun, setDryRun] = useState(initial.dry_run);
  const [minSeverity, setMinSeverity] = useState(initial.min_severity);
  const [useLighthouse, setUseLighthouse] = useState(initial.use_lighthouse);
  const [rows, setRows] = useState<ScopeRow[]>(() =>
    Object.entries(initial.scope_tags).map(([key, value]) =>
      newScopeRow(key, value),
    ),
  );
  const [errors, setErrors] = useState<Record<string, string>>({});
  const [saving, setSaving] = useState(false);

  const save = async () => {
    const scope = scopeRowsToTags(rows);
    const patch: EnforcementPatch = {
      enabled: false,
      mode,
      dry_run: dryRun,
      min_severity: minSeverity,
      frameworks,
      scope_tags: scope.tags,
      use_lighthouse: useLighthouse,
    };
    // Only what this step edits can block it.
    const found = Object.fromEntries(
      Object.entries(
        policyFieldErrors({ ...(policy ?? WIZARD_DEFAULT_POLICY), ...patch }),
      ).filter(([field]) => field in patch),
    );
    if (scope.error) found.scope_tags = scope.error;
    if (Object.keys(found).length > 0) {
      setErrors(found);
      return;
    }
    setErrors({});
    setSaving(true);
    const result = policy
      ? await patchRealtimePolicy({
          providerId,
          policyId: policy.id,
          patch,
        })
      : await saveRealtimePolicy({
          providerId,
          policy: { ...WIZARD_DEFAULT_POLICY, ...patch },
        });
    setSaving(false);
    if (result.ok) {
      onSaved(result.data);
      toast({ title: "Choices saved. Nothing is switched on yet." });
    } else {
      setErrors(result.fieldErrors ?? {});
      toast({
        variant: "destructive",
        title: "Could not save your choices",
        description: result.error,
      });
    }
  };

  return (
    <form
      noValidate
      className="flex flex-col gap-6"
      onSubmit={(event) => {
        event.preventDefault();
        void save();
      }}
    >
      <FrameworkPicker
        catalog={frameworkCatalog}
        selected={frameworks}
        disabled={saving}
        error={errors.frameworks}
        onChange={setFrameworks}
      />

      <fieldset className="flex flex-col gap-3">
        <legend className="text-text-neutral-primary mb-1 text-sm font-medium">
          What Prowler does when it finds a problem
        </legend>
        <RadioGroup
          value={mode}
          disabled={saving}
          onValueChange={(value) => setMode(value as RealtimeMode)}
        >
          {Object.values(REALTIME_MODE).map((value) => (
            <div key={value} className="flex items-start gap-3">
              <RadioGroupItem
                id={`${id}-mode-${value}`}
                value={value}
                aria-describedby={`${id}-mode-${value}-description`}
                className="mt-0.5"
              />
              <div className="flex flex-col gap-0.5">
                <label
                  htmlFor={`${id}-mode-${value}`}
                  className="text-text-neutral-primary flex items-center gap-2 text-sm font-medium"
                >
                  {MODE_DESCRIPTIONS[value].label}
                  {value === REALTIME_MODE.MONITOR && (
                    <Badge variant="tag" size="sm">
                      Default
                    </Badge>
                  )}
                </label>
                <p
                  id={`${id}-mode-${value}-description`}
                  className="text-text-neutral-tertiary max-w-prose text-xs"
                >
                  {MODE_DESCRIPTIONS[value].consequence}
                </p>
              </div>
            </div>
          ))}
        </RadioGroup>
        {errors.mode && <FieldError>{errors.mode}</FieldError>}
      </fieldset>

      <ToggleRow
        id={`${id}-dry-run`}
        label="Dry run"
        description="Record what Prowler Realtime would change in the account without changing it. Applies to Fix automatically. On by default."
        checked={dryRun}
        disabled={saving}
        onChange={setDryRun}
      />
      {mode === REALTIME_MODE.AUTO && !dryRun && (
        <Alert variant="warning">
          <AlertTitle>Dry run is off</AlertTitle>
          <AlertDescription>
            <p>
              Once you activate in the last step, Prowler Realtime will change
              resources in your AWS account as soon as it detects a matching
              risky change. Each change records how to undo it.
            </p>
          </AlertDescription>
        </Alert>
      )}

      <Field className="max-w-xs">
        <FieldLabel htmlFor={`${id}-severity`}>Minimum severity</FieldLabel>
        <Select
          value={minSeverity}
          disabled={saving}
          onValueChange={(value) =>
            setMinSeverity(value as RealtimePolicyInput["min_severity"])
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
        {errors.min_severity && <FieldError>{errors.min_severity}</FieldError>}
      </Field>

      <ScopeTagsEditor
        rows={rows}
        disabled={saving}
        error={errors.scope_tags}
        onChange={setRows}
      />

      <div className="flex flex-col gap-2">
        <ToggleRow
          id={`${id}-lighthouse`}
          label="Let Lighthouse AI write the code change"
          description="For checks without a built-in patcher, Lighthouse AI writes the change using your configured LLM. The Terraform file and the finding are sent to that LLM provider. Pull requests are always reviewed by a person."
          checked={useLighthouse}
          disabled={saving}
          onChange={setUseLighthouse}
        />
        <div className="flex flex-wrap items-center gap-2 pl-14">
          {useLighthouse && lighthouseConfigured === false && (
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
      </div>

      <div className="flex items-center gap-3">
        <Button type="submit" disabled={saving}>
          {saving ? "Saving…" : "Save and continue"}
        </Button>
        {Object.keys(errors).length > 0 && (
          <span role="alert" className="text-text-error-primary text-sm">
            Fix the highlighted fields and try again.
          </span>
        )}
      </div>
    </form>
  );
}
