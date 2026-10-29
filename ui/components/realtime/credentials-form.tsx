"use client";

import { useId, useState } from "react";

import {
  deleteRealtimeCredential,
  saveRealtimeCredential,
} from "@/actions/realtime";
import { RealtimeSection } from "@/components/realtime/realtime-stat-card";
import { RemediationList } from "@/components/realtime/remediation-list";
import { TemplateGuide } from "@/components/realtime/template-guide";
import { Alert, AlertDescription, AlertTitle } from "@/components/shadcn/alert";
import { Badge } from "@/components/shadcn/badge/badge";
import { Button } from "@/components/shadcn/button/button";
import { Field, FieldError, FieldLabel } from "@/components/shadcn/field/field";
import { Input } from "@/components/shadcn/input/input";
import { Modal } from "@/components/shadcn/modal";
import { useToast } from "@/components/shadcn/toast";
import { realtimeCredentialSchema } from "@/lib/realtime/policy-schema";
import {
  REMEDIATION_CLOUDFORMATION,
  REMEDIATION_TERRAFORM,
} from "@/lib/realtime/templates";
import type { RealtimeCredential } from "@/types/realtime";

interface CredentialsFormProps {
  providerId: string;
  credential: RealtimeCredential | null;
  canManage: boolean;
  onChanged: (credential: RealtimeCredential | null) => void;
}

/**
 * Remediation role and GitHub token. Secrets are write-only: the inputs start
 * empty, are cleared after a save, and the API only ever says whether they
 * exist.
 */
export function CredentialsForm({
  providerId,
  credential,
  canManage,
  onChanged,
}: CredentialsFormProps) {
  const { toast } = useToast();
  const id = useId();
  const [roleArn, setRoleArn] = useState("");
  const [externalId, setExternalId] = useState("");
  const [githubToken, setGithubToken] = useState("");
  const [errors, setErrors] = useState<Record<string, string>>({});
  const [saving, setSaving] = useState(false);
  const [confirmRemove, setConfirmRemove] = useState(false);

  const hasRole = Boolean(credential?.role_arn);

  const save = async () => {
    const parsed = realtimeCredentialSchema.safeParse({
      role_arn: roleArn,
      external_id: externalId,
      github_token: githubToken,
    });
    if (!parsed.success) {
      setErrors(
        Object.fromEntries(
          parsed.error.issues.map((issue) => [
            String(issue.path[0]),
            issue.message,
          ]),
        ),
      );
      return;
    }
    setErrors({});
    setSaving(true);
    const result = await saveRealtimeCredential({
      providerId,
      credential: parsed.data,
    });
    setSaving(false);
    if (result.ok) {
      setRoleArn("");
      setExternalId("");
      setGithubToken("");
      onChanged(result.data);
      toast({ title: "Credentials saved" });
    } else {
      setErrors(result.fieldErrors ?? {});
      toast({
        variant: "destructive",
        title: "Could not save the credentials",
        description: result.error,
      });
    }
  };

  const remove = async () => {
    if (!credential) return;
    setSaving(true);
    const result = await deleteRealtimeCredential(credential.id);
    setSaving(false);
    setConfirmRemove(false);
    if (result.ok) {
      onChanged(null);
      toast({ title: "Credentials removed" });
    } else {
      toast({
        variant: "destructive",
        title: "Could not remove the credentials",
        description: result.error,
      });
    }
  };

  return (
    <RealtimeSection
      title="Credentials for remediation only"
      description="Used only to fix the account and open pull requests; detection never needs them. Secrets are never shown again after you save them."
    >
      <ul
        className="flex flex-wrap items-center gap-2"
        aria-label="Stored credentials"
      >
        <li>
          <Badge variant={hasRole ? "success" : "tag"}>
            {hasRole ? "Remediation role set" : "No remediation role"}
          </Badge>
        </li>
        <li>
          <Badge variant={credential?.has_github_token ? "success" : "tag"}>
            {credential?.has_github_token
              ? "GitHub token stored"
              : "No GitHub token"}
          </Badge>
        </li>
      </ul>
      {hasRole && (
        <p className="text-text-neutral-secondary text-sm break-all">
          Role: <code className="text-xs">{credential?.role_arn}</code>
        </p>
      )}

      <Alert variant="info">
        <AlertTitle>Allow Prowler to remediate, in your AWS account</AlertTitle>
        <AlertDescription>
          <p>
            Prowler can only alert and open pull requests until you give it a
            separate role that is allowed to make a small, fixed set of fixes.
            Your scan role stays read-only, and you can delete the role at any
            time to revoke it.
          </p>
        </AlertDescription>
      </Alert>
      <RemediationList providerId={providerId} />
      <TemplateGuide
        cloudformation={REMEDIATION_CLOUDFORMATION}
        terraform={REMEDIATION_TERRAFORM}
        steps={[
          <>
            Pick an <strong>external id</strong> (at least 8 characters) and
            keep it: you enter the same value below.
          </>,
          <>
            Apply the template below in this AWS account, as CloudFormation
            (stack) or Terraform (<code className="text-xs">apply</code>). It
            creates one role named{" "}
            <code className="text-xs">ProwlerRemediation</code> that only
            Prowler Cloud can assume, with your external id.
          </>,
          <>
            Copy the <code className="text-xs">RoleArn</code> output, paste it
            below with the external id, and save.
          </>,
          <>
            Optional: add a GitHub token with permission to create branches and
            pull requests, so fixes in code can be proposed.
          </>,
        ]}
      />

      {canManage ? (
        <form
          className="flex flex-col gap-4"
          autoComplete="off"
          onSubmit={(event) => {
            event.preventDefault();
            void save();
          }}
        >
          <div className="grid grid-cols-1 gap-4 md:grid-cols-2">
            <Field>
              <FieldLabel htmlFor={`${id}-role`}>
                Remediation role ARN
              </FieldLabel>
              <Input
                id={`${id}-role`}
                value={roleArn}
                disabled={saving}
                autoComplete="off"
                placeholder={
                  hasRole
                    ? "Leave empty to keep the stored role"
                    : "arn:aws:iam::123456789012:role/ProwlerRealtimeRemediation"
                }
                aria-invalid={Boolean(errors.role_arn)}
                onChange={(event) => setRoleArn(event.target.value)}
              />
              {errors.role_arn && <FieldError>{errors.role_arn}</FieldError>}
            </Field>
            <Field>
              <FieldLabel htmlFor={`${id}-external`}>External id</FieldLabel>
              <Input
                id={`${id}-external`}
                type="password"
                value={externalId}
                disabled={saving}
                autoComplete="new-password"
                placeholder="Write only"
                aria-invalid={Boolean(errors.external_id)}
                onChange={(event) => setExternalId(event.target.value)}
              />
              {errors.external_id && (
                <FieldError>{errors.external_id}</FieldError>
              )}
            </Field>
          </div>
          <Field className="max-w-xl">
            <FieldLabel htmlFor={`${id}-token`}>GitHub token</FieldLabel>
            <Input
              id={`${id}-token`}
              type="password"
              value={githubToken}
              disabled={saving}
              autoComplete="new-password"
              placeholder={
                credential?.has_github_token
                  ? "Leave empty to keep the stored token"
                  : "Write only"
              }
              aria-invalid={Boolean(errors.github_token)}
              onChange={(event) => setGithubToken(event.target.value)}
            />
            {errors.github_token && (
              <FieldError>{errors.github_token}</FieldError>
            )}
          </Field>
          {errors.form && <FieldError>{errors.form}</FieldError>}
          <div className="flex flex-wrap items-center gap-3">
            <Button type="submit" disabled={saving}>
              {saving ? "Saving…" : "Save credentials"}
            </Button>
            {credential && (
              <Button
                type="button"
                variant="outline"
                disabled={saving}
                onClick={() => setConfirmRemove(true)}
              >
                Remove credentials
              </Button>
            )}
          </div>
        </form>
      ) : (
        <p className="text-text-neutral-tertiary text-sm">
          Read only: changing credentials needs the Manage Realtime permission.
        </p>
      )}

      <Modal
        open={confirmRemove}
        onOpenChange={(open) => {
          if (!open && !saving) setConfirmRemove(false);
        }}
        title="Remove the stored credentials?"
        description="Prowler Realtime can no longer fix this account or open pull requests until you add them again."
        size="lg"
      >
        <div className="flex justify-end gap-2">
          <Button
            variant="outline"
            disabled={saving}
            onClick={() => setConfirmRemove(false)}
          >
            Cancel
          </Button>
          <Button
            variant="destructive"
            disabled={saving}
            onClick={() => void remove()}
          >
            {saving ? "Removing…" : "Remove credentials"}
          </Button>
        </div>
      </Modal>
    </RealtimeSection>
  );
}
