"use client";

import Link from "next/link";
import { useEffect, useRef, useState } from "react";

import { saveDynamicProviderCredentials } from "@/actions/providers/dynamic-provider-credentials";
import { getProviderSchemas } from "@/actions/providers/provider-schemas";
import { RegistryCredentialFields } from "@/components/registry/provider-credential-fields";
import { Alert, AlertDescription, AlertTitle } from "@/components/shadcn/alert";
import { Button } from "@/components/shadcn/button/button";
import { Field, FieldLabel } from "@/components/shadcn/field/field";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/shadcn/select/select";
import { Skeleton } from "@/components/shadcn/skeleton/skeleton";
import { useToast } from "@/components/shadcn/toast";
import {
  parseRegistryCredentialSchema,
  type RegistryCredentialSchema,
} from "@/lib/registry/provider-credential-schema";
import {
  getCredentialDefaults,
  validateCredentialValues,
} from "@/lib/registry/provider-credential-values";
import { useProviderWizardStore } from "@/store/provider-wizard/store";
import type { ProviderSchemasResult } from "@/types/provider-schema";

import {
  WIZARD_FOOTER_ACTION_TYPE,
  type WizardFooterConfig,
} from "./footer-controls";

interface DynamicCredentialsStepProps {
  providerId: string;
  providerType: string;
  onNext: () => void;
  onBack: () => void;
  onFooterChange: (config: WizardFooterConfig) => void;
}

function DynamicCredentialForm({
  providerId,
  secretType,
  schema,
  onNext,
  onBack,
  onFooterChange,
  onLoadingChange,
}: Omit<DynamicCredentialsStepProps, "providerType"> & {
  secretType: string;
  schema: RegistryCredentialSchema;
  onLoadingChange: (value: boolean) => void;
}) {
  const { toast } = useToast();
  const setSecretId = useProviderWizardStore((state) => state.setSecretId);
  // Credentials belong only to this form. A new account or authentication
  // method mounts a fresh instance; no values enter the persisted wizard store.
  const [values, setValues] = useState(() => getCredentialDefaults(schema));
  const [errors, setErrors] = useState<Record<string, string>>({});
  const [saving, setSaving] = useState(false);
  const inFlight = useRef(false);
  const mounted = useRef(true);
  const formId = "provider-wizard-dynamic-credentials-form";
  const valid = validateCredentialValues(schema, values).valid;
  useEffect(() => {
    mounted.current = true;
    return () => {
      mounted.current = false;
    };
  }, []);

  useEffect(() => {
    onFooterChange({
      showBack: true,
      backLabel: "Back",
      backDisabled: saving,
      onBack,
      showAction: true,
      actionLabel: "Authenticate",
      actionDisabled: saving || !valid,
      actionType: WIZARD_FOOTER_ACTION_TYPE.SUBMIT,
      actionFormId: formId,
    });
  }, [onBack, onFooterChange, saving, valid]);

  return (
    <form
      id={formId}
      onSubmit={async (event) => {
        event.preventDefault();
        if (inFlight.current) return;
        const validation = validateCredentialValues(schema, values);
        setErrors(validation.errors);
        if (!validation.valid) return;
        inFlight.current = true;
        setSaving(true);
        onLoadingChange(true);
        try {
          const result = await saveDynamicProviderCredentials({
            providerId,
            secretType,
            secret: validation.secret,
          });
          if (!mounted.current) return;
          if (result.status === "saved") {
            setValues({});
            setSecretId(result.secretId);
            toast({
              title: "Credentials saved",
              description: "Test the provider connection to continue.",
            });
            onNext();
          } else if (result.status === "invalid") {
            setErrors(result.errors);
          } else {
            const description =
              result.status === "schema_unavailable"
                ? "The credential schema is unavailable. Check the installed artifact in Registry and reload the form."
                : result.status === "access_denied"
                  ? "You no longer have permission to update these credentials. Contact an administrator."
                  : "Check your credentials and try again. Your provider account is already created.";
            setErrors({ _form: description });
            toast({
              variant: "destructive",
              title: "Credentials could not be saved",
              description,
            });
          }
        } catch {
          if (mounted.current) {
            const description =
              "Could not save the credentials. Check your connection and retry.";
            setErrors({ _form: description });
            toast({
              variant: "destructive",
              title: "Credentials could not be saved",
              description,
            });
          }
        } finally {
          inFlight.current = false;
          if (mounted.current) {
            setSaving(false);
            onLoadingChange(false);
          }
        }
      }}
    >
      <fieldset disabled={saving} className="flex flex-col gap-4">
        {errors._form && (
          <Alert variant="error">
            <AlertTitle>Credentials could not be saved</AlertTitle>
            <AlertDescription>{errors._form}</AlertDescription>
          </Alert>
        )}
        <RegistryCredentialFields
          schema={schema}
          values={values}
          errors={errors}
          onChange={(name, value) => {
            setValues((current) => ({ ...current, [name]: value }));
            setErrors({});
          }}
        />
      </fieldset>
    </form>
  );
}

function DynamicCredentialsContent(props: DynamicCredentialsStepProps) {
  const { providerType, onBack, onFooterChange } = props;
  const [schemas, setSchemas] = useState<ProviderSchemasResult | null>(null);
  const [selectedMethod, setSelectedMethod] = useState("");
  const [attempt, setAttempt] = useState(0);
  const [saving, setSaving] = useState(false);
  useEffect(() => {
    let active = true;
    setSchemas(null);
    setSelectedMethod("");
    getProviderSchemas(providerType)
      .then((result) => {
        if (active) setSchemas(result);
      })
      .catch(() => {
        if (active) setSchemas({ status: "error" });
      });
    return () => {
      active = false;
    };
  }, [providerType, attempt]);

  const methods =
    schemas?.status === "success" ? Object.keys(schemas.secretTypes) : [];
  const secretType = selectedMethod || methods[0];
  const schema =
    schemas?.status === "success" && secretType
      ? parseRegistryCredentialSchema(schemas.secretTypes[secretType])
      : null;
  useEffect(() => {
    if (!schema)
      onFooterChange({
        showBack: true,
        backLabel: "Back",
        onBack,
        showAction: false,
        actionLabel: "Authenticate",
        actionType: WIZARD_FOOTER_ACTION_TYPE.BUTTON,
      });
  }, [schema, onBack, onFooterChange]);

  if (!schemas)
    return (
      <div
        role="status"
        aria-label="Loading credential schema"
        className="space-y-4"
      >
        <Skeleton className="h-10 w-full" />
        <Skeleton className="h-10 w-full" />
      </div>
    );

  return (
    <div className="flex flex-col gap-6">
      {methods.length > 1 && (
        <Field>
          <FieldLabel htmlFor="registry-auth-method">
            Authentication method
          </FieldLabel>
          <Select
            value={secretType}
            disabled={saving}
            onValueChange={setSelectedMethod}
          >
            <SelectTrigger id="registry-auth-method">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              {methods.map((method) => (
                <SelectItem key={method} value={method}>
                  {method.replaceAll("_", " ")}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        </Field>
      )}
      {schema ? (
        <DynamicCredentialForm
          key={`${secretType}/${attempt}`}
          {...props}
          secretType={secretType}
          schema={schema}
          onLoadingChange={setSaving}
        />
      ) : (
        <Alert variant="error">
          <AlertTitle>Credential schema unavailable</AlertTitle>
          <AlertDescription>
            <p>
              This provider does not describe a supported credential form. Check
              that its artifact is installed and up to date, or contact its
              publisher.
            </p>
            <div className="flex flex-wrap gap-3">
              <Button
                type="button"
                variant="outline"
                onClick={() => setAttempt((value) => value + 1)}
              >
                Reload credential schema
              </Button>
              <Button variant="link" asChild>
                <Link href="/registry">Open Registry</Link>
              </Button>
            </div>
          </AlertDescription>
        </Alert>
      )}
    </div>
  );
}

export function DynamicCredentialsStep(props: DynamicCredentialsStepProps) {
  return (
    <DynamicCredentialsContent
      key={`${props.providerId}/${props.providerType}`}
      {...props}
    />
  );
}
