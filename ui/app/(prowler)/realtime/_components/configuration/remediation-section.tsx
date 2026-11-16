"use client";

import { zodResolver } from "@hookform/resolvers/zod";
import { ChevronDown } from "lucide-react";
import { useState } from "react";
import { useForm, useFormState } from "react-hook-form";

import {
  deleteRealtimeCredential,
  saveRealtimeCredential,
} from "@/app/(prowler)/realtime/_actions";
import { ConfirmModal } from "@/app/(prowler)/realtime/_components/shared/confirm-modal";
import {
  credentialFormSchema,
  type CredentialFormValues,
  EMPTY_CREDENTIAL_FORM,
} from "@/app/(prowler)/realtime/_lib/configuration-forms";
import { remediationSummary } from "@/app/(prowler)/realtime/_lib/setup";
import {
  REMEDIATION_CLOUDFORMATION,
  REMEDIATION_TERRAFORM,
} from "@/app/(prowler)/realtime/_lib/templates";
import type {
  RealtimeCredential,
  RealtimeRemediation,
} from "@/app/(prowler)/realtime/_types";
import {
  Badge,
  Button,
  Field,
  FieldError,
  FieldLabel,
  Input,
} from "@/components/shadcn";
import {
  Collapsible,
  CollapsibleContent,
  CollapsibleTrigger,
} from "@/components/shadcn/collapsible";
import { toast } from "@/components/shadcn/toast";

import { ConfigSectionCard, SectionFooter } from "./config-section-card";
import { reportSaveFailure, type SectionBaseProps } from "./section-props";
import { TemplateGuide } from "./template-guide";

const CREDENTIAL_FIELDS = ["role_arn", "external_id", "github_token"] as const;

interface RemediationSectionProps extends SectionBaseProps {
  credential: RealtimeCredential | null;
  remediations: RealtimeRemediation[];
}

export function RemediationSection(props: RemediationSectionProps) {
  return (
    <ConfigSectionCard
      id="remediation"
      number={props.number}
      title="Remediation access"
      description="A remediation-only role to fix the account, and a GitHub token to open pull requests. Both are optional."
      summary={remediationSummary(props.credential)}
      state={props.state}
      required={props.required}
      open={props.open}
      onOpen={props.onOpen}
    >
      <RemediationForm {...props} />
    </ConfigSectionCard>
  );
}

function RemediationForm({
  credential,
  remediations,
  providerId,
  canManage,
  onClose,
  onSaved,
}: RemediationSectionProps) {
  const [confirmRemove, setConfirmRemove] = useState(false);
  const [removing, setRemoving] = useState(false);
  const form = useForm<CredentialFormValues>({
    resolver: zodResolver(credentialFormSchema),
    defaultValues: EMPTY_CREDENTIAL_FORM,
  });
  const { errors, isSubmitting } = useFormState({ control: form.control });

  const submit = async (values: CredentialFormValues) => {
    const result = await saveRealtimeCredential({
      providerId,
      credential: values,
    });
    if (!result.ok) {
      reportSaveFailure(
        result,
        form.setError,
        CREDENTIAL_FIELDS,
        "Credentials not saved",
      );
      return;
    }
    // Secrets are write-only: never keep them in the page.
    form.reset(EMPTY_CREDENTIAL_FORM);
    toast({ title: "Credentials saved" });
    onSaved();
  };

  const remove = async () => {
    if (!credential) return;
    setRemoving(true);
    const result = await deleteRealtimeCredential(credential.id);
    setRemoving(false);
    if (!result.ok) {
      toast({
        variant: "destructive",
        title: "Credentials not removed",
        description: result.error,
      });
      return;
    }
    setConfirmRemove(false);
    toast({ title: "Credentials removed" });
    onSaved();
  };

  return (
    <>
      <form onSubmit={form.handleSubmit(submit)} noValidate>
        <fieldset
          disabled={!canManage}
          className="flex flex-col gap-6 px-[18px] py-4"
        >
          <legend className="sr-only">Remediation access</legend>
          <div className="flex flex-wrap items-center gap-2">
            <Badge variant={credential?.role_arn ? "success" : "tag"}>
              {credential?.role_arn
                ? "Remediation role set"
                : "No remediation role"}
            </Badge>
            <Badge variant={credential?.has_github_token ? "success" : "tag"}>
              {credential?.has_github_token
                ? "GitHub token stored"
                : "No GitHub token"}
            </Badge>
            {credential?.role_arn && (
              <span className="text-text-neutral-tertiary font-mono text-xs break-all">
                {credential.role_arn}
              </span>
            )}
          </div>

          <RemediationList remediations={remediations} />

          <TemplateGuide
            cloudformation={REMEDIATION_CLOUDFORMATION}
            terraform={REMEDIATION_TERRAFORM}
            steps={[
              "Choose an external id of at least 8 characters.",
              "Deploy the template in this AWS account with that external id.",
              "Paste the RoleArn output and the external id below.",
            ]}
          />

          <div className="grid gap-4 md:grid-cols-2">
            <Field>
              <FieldLabel htmlFor="remediation-role">
                Remediation role ARN
              </FieldLabel>
              <Input
                id="remediation-role"
                placeholder="arn:aws:iam::123456789012:role/ProwlerRemediation"
                autoComplete="off"
                aria-invalid={Boolean(errors.role_arn)}
                {...form.register("role_arn")}
              />
              {errors.role_arn && (
                <FieldError>{errors.role_arn.message}</FieldError>
              )}
            </Field>
            <Field>
              <FieldLabel htmlFor="remediation-external-id">
                External id
              </FieldLabel>
              <Input
                id="remediation-external-id"
                type="password"
                autoComplete="off"
                aria-invalid={Boolean(errors.external_id)}
                {...form.register("external_id")}
              />
              {errors.external_id && (
                <FieldError>{errors.external_id.message}</FieldError>
              )}
            </Field>
            <Field className="md:col-span-2">
              <FieldLabel htmlFor="remediation-github-token">
                GitHub token
              </FieldLabel>
              <Input
                id="remediation-github-token"
                type="password"
                autoComplete="off"
                aria-invalid={Boolean(errors.github_token)}
                {...form.register("github_token")}
              />
              <span className="text-text-neutral-tertiary text-xs">
                Needs write access to the repository to push a branch and open
                pull requests. Stored encrypted and never shown again.
              </span>
              {errors.github_token && (
                <FieldError>{errors.github_token.message}</FieldError>
              )}
            </Field>
          </div>

          {credential && (
            <div className="flex">
              <Button
                type="button"
                variant="outline"
                size="sm"
                onClick={() => setConfirmRemove(true)}
              >
                Remove credentials
              </Button>
            </div>
          )}
        </fieldset>
        <SectionFooter
          onCancel={onClose}
          submitLabel="Save credentials"
          pending={isSubmitting}
          disabled={!canManage}
        />
      </form>
      <ConfirmModal
        open={confirmRemove}
        onOpenChange={setConfirmRemove}
        title="Remove the credentials?"
        description="Prowler stops fixing this account and opening pull requests. Alerts and proposals keep working."
        confirmLabel="Remove"
        destructive
        pending={removing}
        onConfirm={remove}
      />
    </>
  );
}

function RemediationList({
  remediations,
}: {
  remediations: RealtimeRemediation[];
}) {
  if (remediations.length === 0) return null;
  return (
    <div className="flex flex-col gap-2">
      <h3 className="text-text-neutral-primary text-sm font-semibold">
        What this role lets Prowler do, and nothing else
      </h3>
      <ul className="border-border-neutral-secondary divide-border-neutral-secondary divide-y rounded-lg border">
        {remediations.map((remediation) => (
          <li key={remediation.id} className="flex flex-col gap-1.5 px-4 py-3">
            <div className="flex flex-wrap items-center gap-2">
              <span className="text-text-neutral-primary text-sm font-medium">
                {remediation.title}
              </span>
              <Badge variant={remediation.revertible ? "success" : "warning"}>
                {remediation.revertible ? "Can be undone" : "Cannot be undone"}
              </Badge>
              {!remediation.in_enforced_scope && (
                <Badge variant="tag">
                  Outside the enforced compliance frameworks
                </Badge>
              )}
            </div>
            <p className="text-text-neutral-secondary text-xs">
              {remediation.effect}
            </p>
            <Collapsible>
              <CollapsibleTrigger asChild>
                <Button
                  type="button"
                  variant="link"
                  size="link-sm"
                  className="group"
                >
                  Exact AWS permissions ({remediation.iam_actions.length})
                  <ChevronDown
                    aria-hidden
                    className="size-3.5 transition-transform group-data-[state=open]:rotate-180"
                  />
                </Button>
              </CollapsibleTrigger>
              <CollapsibleContent>
                <ul className="text-text-neutral-secondary flex flex-wrap gap-x-3 gap-y-1 pt-1 font-mono text-xs">
                  {remediation.iam_actions.map((action) => (
                    <li key={action}>{action}</li>
                  ))}
                </ul>
              </CollapsibleContent>
            </Collapsible>
          </li>
        ))}
      </ul>
    </div>
  );
}
