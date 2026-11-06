"use client";

import { zodResolver } from "@hookform/resolvers/zod";
import { ChevronDown, Plus, X } from "lucide-react";
import Link from "next/link";
import {
  Controller,
  useFieldArray,
  useForm,
  useFormState,
  useWatch,
} from "react-hook-form";

import {
  patchRealtimePolicy,
  saveRealtimePolicy,
} from "@/app/(prowler)/realtime/_actions";
import {
  ENFORCEMENT_FIELDS,
  type EnforcementFormValues,
  enforcementFormDefaults,
  enforcementFormSchema,
  toEnforcementPatch,
} from "@/app/(prowler)/realtime/_lib/configuration-forms";
import {
  frameworkLabel,
  MODE_DESCRIPTIONS,
} from "@/app/(prowler)/realtime/_lib/display";
import { DEFAULT_REALTIME_POLICY } from "@/app/(prowler)/realtime/_lib/policy-schema";
import { enforcementSummary } from "@/app/(prowler)/realtime/_lib/setup";
import {
  REALTIME_MAX_FRAMEWORKS,
  REALTIME_MAX_SCOPE_TAGS,
  REALTIME_MIN_SEVERITY,
  REALTIME_MODE,
  type RealtimeFramework,
  type RealtimePolicy,
} from "@/app/(prowler)/realtime/_types";
import {
  Alert,
  AlertDescription,
  Button,
  Field,
  FieldError,
  FieldLabel,
  Input,
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
  Switch,
  Textarea,
} from "@/components/shadcn";
import {
  Collapsible,
  CollapsibleContent,
  CollapsibleTrigger,
} from "@/components/shadcn/collapsible";
import {
  RadioGroup,
  RadioGroupItem,
} from "@/components/shadcn/radio-group/radio-group";
import {
  MultiSelect,
  MultiSelectContent,
  MultiSelectItem,
  MultiSelectTrigger,
  MultiSelectValue,
} from "@/components/shadcn/select/multiselect";
import { toast } from "@/components/shadcn/toast";
import { cn } from "@/lib/utils";

import { ConfigSectionCard, SectionFooter } from "./config-section-card";
import { reportSaveFailure, type SectionBaseProps } from "./section-props";

const LIGHTHOUSE_SETTINGS_PATH = "/lighthouse/settings";
const MODE_ORDER = [
  REALTIME_MODE.MONITOR,
  REALTIME_MODE.PR,
  REALTIME_MODE.AUTO,
] as const;
const SEVERITY_OPTIONS = [
  { value: REALTIME_MIN_SEVERITY.LOW, label: "Low and above" },
  { value: REALTIME_MIN_SEVERITY.MEDIUM, label: "Medium and above" },
  { value: REALTIME_MIN_SEVERITY.HIGH, label: "High and above" },
  { value: REALTIME_MIN_SEVERITY.CRITICAL, label: "Critical only" },
] as const;

interface EnforcementSectionProps extends SectionBaseProps {
  policy: RealtimePolicy | null;
  frameworks: RealtimeFramework[];
  lighthouseConfigured: boolean;
}

export function EnforcementSection(props: EnforcementSectionProps) {
  return (
    <ConfigSectionCard
      id="enforcement"
      number={props.number}
      title="What to enforce"
      description="How Prowler responds when a change breaks a check."
      summary={enforcementSummary(props.policy, props.frameworks)}
      state={props.state}
      required={props.required}
      open={props.open}
      onOpen={props.onOpen}
    >
      <EnforcementForm {...props} />
    </ConfigSectionCard>
  );
}

function SwitchRow({
  id,
  label,
  hint,
  checked,
  onCheckedChange,
}: {
  id: string;
  label: string;
  hint: string;
  checked: boolean;
  onCheckedChange: (checked: boolean) => void;
}) {
  return (
    <div className="flex items-start justify-between gap-4">
      <span className="flex flex-col gap-0.5">
        <label
          htmlFor={id}
          className="text-text-neutral-primary text-sm font-medium"
        >
          {label}
        </label>
        <span className="text-text-neutral-tertiary text-xs">{hint}</span>
      </span>
      <Switch id={id} checked={checked} onCheckedChange={onCheckedChange} />
    </div>
  );
}

function EnforcementForm({
  policy,
  frameworks,
  lighthouseConfigured,
  providerId,
  canManage,
  onClose,
  onSaved,
}: EnforcementSectionProps) {
  const form = useForm<EnforcementFormValues>({
    resolver: zodResolver(enforcementFormSchema),
    defaultValues: enforcementFormDefaults(policy),
  });
  const scopeTags = useFieldArray({
    control: form.control,
    name: "scope_tags",
  });
  const [mode, dryRun, selectedFrameworks] = useWatch({
    control: form.control,
    name: ["mode", "dry_run", "frameworks"],
  });
  const { errors, isSubmitting } = useFormState({ control: form.control });

  const submit = async (values: EnforcementFormValues) => {
    const patch = toEnforcementPatch(values);
    const result = policy
      ? await patchRealtimePolicy({ providerId, policyId: policy.id, patch })
      : await saveRealtimePolicy({
          providerId,
          // A new policy stays off until the Activate step.
          policy: { ...DEFAULT_REALTIME_POLICY, ...patch, enabled: false },
        });
    if (!result.ok) {
      reportSaveFailure(
        result,
        form.setError,
        ENFORCEMENT_FIELDS,
        "Policy not saved",
      );
      return;
    }
    toast({ title: "Policy saved" });
    onSaved();
  };

  const atFrameworkLimit = selectedFrameworks.length >= REALTIME_MAX_FRAMEWORKS;
  const scopeError =
    errors.scope_tags?.root?.message ?? errors.scope_tags?.message;

  return (
    <form onSubmit={form.handleSubmit(submit)} noValidate>
      <fieldset
        disabled={!canManage}
        className="flex flex-col gap-6 px-[18px] py-4"
      >
        <legend className="sr-only">What to enforce</legend>

        <div className="flex flex-col gap-3">
          <span
            id="enforcement-mode-label"
            className="text-text-neutral-primary text-sm font-medium"
          >
            Response
          </span>
          <Controller
            control={form.control}
            name="mode"
            render={({ field }) => (
              <RadioGroup
                value={field.value}
                onValueChange={field.onChange}
                aria-labelledby="enforcement-mode-label"
                className="grid gap-3 lg:grid-cols-3"
              >
                {MODE_ORDER.map((value) => (
                  <label
                    key={value}
                    className={cn(
                      "border-border-input-primary bg-bg-input-primary flex cursor-pointer items-start gap-3 rounded-lg border px-4 py-3",
                      field.value === value && "border-button-primary",
                    )}
                  >
                    <RadioGroupItem value={value} className="mt-0.5" />
                    <span className="flex flex-col gap-0.5">
                      <span className="text-text-neutral-primary text-sm font-medium">
                        {MODE_DESCRIPTIONS[value].label}
                      </span>
                      <span className="text-text-neutral-tertiary text-xs">
                        {MODE_DESCRIPTIONS[value].consequence}
                      </span>
                    </span>
                  </label>
                ))}
              </RadioGroup>
            )}
          />
          {mode === REALTIME_MODE.AUTO && (
            <div className="bg-bg-neutral-tertiary border-border-neutral-secondary flex flex-col gap-3 rounded-lg border px-4 py-3">
              <Controller
                control={form.control}
                name="dry_run"
                render={({ field }) => (
                  <SwitchRow
                    id="enforcement-dry-run"
                    label="Dry run"
                    hint="Record what would be fixed without changing the account. Turn it off once the log looks right."
                    checked={field.value}
                    onCheckedChange={field.onChange}
                  />
                )}
              />
              {!dryRun && (
                <Alert variant="warning">
                  <AlertDescription>
                    Prowler will change this AWS account as soon as a supported
                    check fails. Every fix records how to undo it.
                  </AlertDescription>
                </Alert>
              )}
            </div>
          )}
        </div>

        <div className="grid gap-4 md:grid-cols-[minmax(0,2fr)_minmax(0,1fr)]">
          <Field>
            <FieldLabel>Enforced compliance frameworks</FieldLabel>
            <Controller
              control={form.control}
              name="frameworks"
              render={({ field }) => (
                <MultiSelect
                  values={field.value}
                  onValuesChange={field.onChange}
                >
                  <MultiSelectTrigger
                    size="sm"
                    aria-label="Enforced compliance frameworks"
                    disabled={!canManage}
                  >
                    <MultiSelectValue placeholder="Every check" />
                  </MultiSelectTrigger>
                  <MultiSelectContent>
                    {frameworks.map((framework) => (
                      <MultiSelectItem
                        key={framework.id}
                        value={framework.id}
                        keywords={[framework.name, framework.version]}
                        disabled={
                          atFrameworkLimit &&
                          !field.value.includes(framework.id)
                        }
                      >
                        {frameworkLabel(framework.id, frameworks)}
                      </MultiSelectItem>
                    ))}
                  </MultiSelectContent>
                </MultiSelect>
              )}
            />
            <span className="text-text-neutral-tertiary text-xs">
              Remediation only acts on checks in these frameworks. Up to{" "}
              {REALTIME_MAX_FRAMEWORKS}. Empty means every check.
            </span>
            {errors.frameworks && (
              <FieldError>{errors.frameworks.message}</FieldError>
            )}
          </Field>
          <Field>
            <FieldLabel htmlFor="enforcement-severity">
              Minimum severity
            </FieldLabel>
            <Controller
              control={form.control}
              name="min_severity"
              render={({ field }) => (
                <Select value={field.value} onValueChange={field.onChange}>
                  <SelectTrigger
                    id="enforcement-severity"
                    size="sm"
                    disabled={!canManage}
                  >
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    {SEVERITY_OPTIONS.map((option) => (
                      <SelectItem key={option.value} value={option.value}>
                        {option.label}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              )}
            />
          </Field>
        </div>

        <div className="flex flex-col gap-2">
          <span className="text-text-neutral-primary text-sm font-medium">
            Resource scope
          </span>
          {scopeTags.fields.map((row, index) => (
            <div
              key={row.id}
              className="grid grid-cols-[minmax(0,1fr)_minmax(0,1fr)_auto] items-start gap-2"
            >
              <Field>
                <Input
                  inputSize="sm"
                  aria-label={`Tag key ${index + 1}`}
                  placeholder="Key"
                  aria-invalid={Boolean(errors.scope_tags?.[index]?.key)}
                  {...form.register(`scope_tags.${index}.key`)}
                />
                {errors.scope_tags?.[index]?.key && (
                  <FieldError>
                    {errors.scope_tags[index]?.key?.message}
                  </FieldError>
                )}
              </Field>
              <Field>
                <Input
                  inputSize="sm"
                  aria-label={`Tag value ${index + 1}`}
                  placeholder="Value"
                  aria-invalid={Boolean(errors.scope_tags?.[index]?.value)}
                  {...form.register(`scope_tags.${index}.value`)}
                />
                {errors.scope_tags?.[index]?.value && (
                  <FieldError>
                    {errors.scope_tags[index]?.value?.message}
                  </FieldError>
                )}
              </Field>
              <Button
                type="button"
                variant="ghost"
                size="icon-sm"
                aria-label={`Remove tag ${index + 1}`}
                onClick={() => scopeTags.remove(index)}
              >
                <X aria-hidden />
              </Button>
            </div>
          ))}
          <div className="flex flex-wrap items-center justify-between gap-2">
            <Button
              type="button"
              variant="outline"
              size="sm"
              disabled={scopeTags.fields.length >= REALTIME_MAX_SCOPE_TAGS}
              onClick={() => scopeTags.append({ key: "", value: "" })}
            >
              <Plus aria-hidden /> Add tag
            </Button>
            <span className="text-text-neutral-tertiary text-xs">
              {scopeTags.fields.length
                ? "Only resources with every tag are checked. Account-level controls such as root MFA are skipped."
                : "No tags: the whole account is in scope."}
            </span>
          </div>
          {scopeError && <FieldError>{scopeError}</FieldError>}
        </div>

        <Collapsible className="border-border-neutral-secondary border-t pt-4">
          <CollapsibleTrigger asChild>
            <Button
              type="button"
              variant="ghost"
              size="sm"
              className="group -ml-2"
            >
              <ChevronDown
                aria-hidden
                className="transition-transform group-data-[state=open]:rotate-180"
              />
              Exclusions
            </Button>
          </CollapsibleTrigger>
          <CollapsibleContent className="grid gap-4 pt-3 md:grid-cols-2">
            <Field>
              <FieldLabel htmlFor="enforcement-deny">
                Never fix automatically (check ids)
              </FieldLabel>
              <Textarea
                id="enforcement-deny"
                rows={3}
                {...form.register("deny_checks")}
              />
              <span className="text-text-neutral-tertiary text-xs">
                One per line, or separated by commas. For example:
                rds_instance_no_public_access.
              </span>
            </Field>
            <Field>
              <FieldLabel htmlFor="enforcement-regions">
                Only fix in these regions
              </FieldLabel>
              <Input
                id="enforcement-regions"
                {...form.register("allow_regions")}
              />
              <span className="text-text-neutral-tertiary text-xs">
                Separated by commas, for example: eu-west-1, us-east-1. Empty
                means every region.
              </span>
            </Field>
          </CollapsibleContent>
        </Collapsible>

        {mode !== REALTIME_MODE.MONITOR && (
          <div className="border-border-neutral-secondary flex flex-col gap-4 border-t pt-4">
            <h3 className="text-text-neutral-primary text-sm font-semibold">
              Changes in code
            </h3>
            <div className="grid gap-4 md:grid-cols-2">
              <Field>
                <FieldLabel htmlFor="enforcement-repo">
                  GitHub repository
                </FieldLabel>
                <Input
                  id="enforcement-repo"
                  placeholder="owner/repository"
                  aria-invalid={Boolean(errors.iac_repo)}
                  {...form.register("iac_repo")}
                />
                {errors.iac_repo && (
                  <FieldError>{errors.iac_repo.message}</FieldError>
                )}
              </Field>
              <Field>
                <FieldLabel htmlFor="enforcement-path">
                  Terraform directory
                </FieldLabel>
                <Input
                  id="enforcement-path"
                  aria-invalid={Boolean(errors.iac_path)}
                  {...form.register("iac_path")}
                />
                <span className="text-text-neutral-tertiary text-xs">
                  Relative to the repository root, for example: infra/terraform.
                </span>
                {errors.iac_path && (
                  <FieldError>{errors.iac_path.message}</FieldError>
                )}
              </Field>
            </div>
            <Controller
              control={form.control}
              name="open_pr"
              render={({ field }) => (
                <SwitchRow
                  id="enforcement-open-pr"
                  label="Open pull requests"
                  hint="Off: the change is prepared and checked, but not pushed."
                  checked={field.value}
                  onCheckedChange={field.onChange}
                />
              )}
            />
            <Controller
              control={form.control}
              name="use_lighthouse"
              render={({ field }) => (
                <SwitchRow
                  id="enforcement-lighthouse"
                  label="Let Lighthouse AI write the change"
                  hint="For checks without a built-in patch. Up to 60 changed lines, never scripts or provisioners."
                  checked={field.value}
                  onCheckedChange={field.onChange}
                />
              )}
            />
            {!lighthouseConfigured && (
              <Alert variant="warning">
                <AlertDescription>
                  <span>
                    Lighthouse AI has no model connected, so it cannot write
                    changes yet.{" "}
                    <Button variant="link" size="link-sm" asChild>
                      <Link href={LIGHTHOUSE_SETTINGS_PATH}>
                        Open Lighthouse AI settings
                      </Link>
                    </Button>
                  </span>
                </AlertDescription>
              </Alert>
            )}
          </div>
        )}
      </fieldset>
      <SectionFooter
        onCancel={onClose}
        submitLabel={policy ? "Save" : "Save and continue"}
        pending={isSubmitting}
        disabled={!canManage}
      />
    </form>
  );
}
