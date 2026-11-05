"use client";

import { RotateCcw } from "lucide-react";
import Link from "next/link";
import { useEffect, useRef, useState } from "react";

import { saveDynamicProviderCredentials } from "@/actions/providers/dynamic-provider-credentials";
import { getProviderSchemas } from "@/actions/providers/provider-schemas";
import { RegistryCredentialFields } from "@/components/providers/workflow/provider-credential-fields";
import { Button } from "@/components/shadcn/button/button";
import { Field, FieldError, FieldLabel } from "@/components/shadcn/field/field";
import { Input } from "@/components/shadcn/input/input";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/shadcn/select/select";
import { Skeleton } from "@/components/shadcn/skeleton/skeleton";
import { StatusAlert } from "@/components/shared/status-alert";
import {
  parseRegistryCredentialVariants,
  type RegistryCredentialSchema,
} from "@/lib/provider-credentials/provider-credential-schema";
import {
  getCredentialDefaults,
  validateCredentialValues,
} from "@/lib/provider-credentials/provider-credential-values";
import {
  ACCOUNT_SUBMIT_OUTCOME,
  dispatchProviderFunnel,
  PROVIDER_FUNNEL_STEP,
} from "@/lib/provider-funnel/provider-funnel-events";
import { formatRegistryLabel } from "@/lib/registry/labels";
import { useProviderWizardStore } from "@/store/provider-wizard/store";
import type {
  ProviderSchemasResult,
  ProviderSecretTypes,
} from "@/types/provider-schema";

import { getUidFieldDetails } from "./connect-methods";
import {
  connectProviderAccount,
  UID_ERROR_POINTER,
} from "./connect-provider-account";
import { ConnectionFeedback } from "./connection-feedback";
import type { ConnectFormProps } from "./types";
import {
  resolveConnectActionLabel,
  useConnectionCheck,
} from "./use-connection-check";

const UID_FIELD = "_uid";
const ALIAS_FIELD = "_alias";
const FORM_ERROR = "_form";

interface CredentialMethod {
  id: string;
  secretType: string;
  label: string;
  schema: RegistryCredentialSchema | null;
}

// Each variant of a secret type's schema is a method of its own.
function listCredentialMethods(
  secretTypes: ProviderSecretTypes,
): CredentialMethod[] {
  return Object.entries(secretTypes).flatMap(([secretType, value]) => {
    const label = formatRegistryLabel(secretType);
    const variants = parseRegistryCredentialVariants(value);
    if (!variants || variants.length === 1) {
      return [
        {
          id: secretType,
          secretType,
          label,
          schema: variants?.[0].schema ?? null,
        },
      ];
    }
    return variants.map((variant, index) => ({
      id: `${secretType}/${index}`,
      secretType,
      label: variant.label ?? `${label} ${index + 1}`,
      schema: variant.schema,
    }));
  });
}

function credentialFormError(status: ProviderSchemasResult["status"]) {
  switch (status) {
    case "access_denied":
      return {
        title: "Access required",
        description:
          "Your session may have expired or you may not have permission. Sign in again or contact your administrator.",
      };
    case "unavailable":
      return {
        title: "Provider installation unavailable",
        description:
          "Install this provider's artifact again in Registry, then try again.",
      };
    case "not_found":
      return {
        title: "Credential form unavailable",
        description:
          "This provider does not provide a credential form. Contact its publisher or your administrator.",
      };
    case "success":
    case "malformed":
      return {
        title: "Credential form not supported",
        description:
          "We could not display this provider's credential form. Contact its publisher or your administrator.",
      };
    default:
      return {
        title: "Could not load credential form",
        description: "Check your connection and try again.",
      };
  }
}

const saveFailureMessage = (status: string) =>
  status === "schema_unavailable"
    ? "The credential schema is unavailable. Check the installed artifact in Registry and reload the form."
    : status === "access_denied"
      ? "You no longer have permission to update these credentials. Contact an administrator."
      : "Check your credentials and try again. Your provider account is already created.";

const savedAccount = (providerType: string) => {
  const store = useProviderWizardStore.getState();
  return store.providerType === providerType
    ? { uid: store.providerUid ?? "", alias: store.providerAlias ?? "" }
    : { uid: "", alias: "" };
};

interface RegistryCredentialFormProps extends ConnectFormProps {
  providerType: string;
  secretType: string;
  schema: RegistryCredentialSchema;
}

function RegistryCredentialForm({
  providerType,
  secretType,
  schema,
  formId,
  locked,
  submitLabel,
  onConnected,
  onBusyChange,
  onUiStateChange,
}: RegistryCredentialFormProps) {
  // Credentials belong only to this form. A new account or authentication
  // method mounts a fresh instance; no values enter the persisted wizard store.
  const [values, setValues] = useState(() => getCredentialDefaults(schema));
  // A remount (back from the launch step) keeps the account already saved for
  // this provider; another provider's account never leaks into the form.
  const [uid, setUid] = useState(() => savedAccount(providerType).uid);
  const [alias, setAlias] = useState(() => savedAccount(providerType).alias);
  const [errors, setErrors] = useState<Record<string, string>>({});
  const [saving, setSaving] = useState(false);
  const inFlight = useRef(false);
  const connection = useConnectionCheck(onConnected);
  const uidField = getUidFieldDetails(providerType);
  const credentialsValid = validateCredentialValues(schema, values).valid;
  const canSubmit = credentialsValid && (locked || uid.trim().length > 0);
  const isBusy = saving || connection.isTesting;

  useEffect(() => {
    onBusyChange(isBusy);
    onUiStateChange({
      showBack: true,
      showAction: true,
      actionLabel: resolveConnectActionLabel({
        submitLabel,
        isTesting: connection.isTesting,
        isSubmitting: saving,
        hasFailed: connection.error !== null,
        hasPending: connection.pending !== null,
      }),
      actionDisabled: !canSubmit || isBusy,
      isLoading: isBusy,
    });
  }, [
    canSubmit,
    connection.error,
    connection.isTesting,
    connection.pending,
    isBusy,
    onBusyChange,
    onUiStateChange,
    saving,
    submitLabel,
  ]);

  const clearError = (name: string) => {
    connection.clear();
    setErrors((current) => {
      const next = { ...current };
      delete next[name];
      return next;
    });
  };

  const submit = async () => {
    const validation = validateCredentialValues(schema, values);
    const identityErrors: Record<string, string> =
      locked || uid.trim()
        ? {}
        : { [UID_FIELD]: `${uidField.label} is required` };
    setErrors({ ...validation.errors, ...identityErrors });
    if (!validation.valid || Object.keys(identityErrors).length > 0) return;

    connection.clear();
    const account = await connectProviderAccount({
      providerType,
      method: secretType,
      uid: uid.trim(),
      alias: locked ? undefined : alias,
      secretValues: {},
      locked,
      skipSecret: true,
    });
    if (!account.ok) {
      const next: Record<string, string> = {};
      account.errors.forEach((error) => {
        const pointer = error.source?.pointer;
        const field =
          pointer === UID_ERROR_POINTER ||
          pointer === "/data/attributes/__all__"
            ? UID_FIELD
            : pointer === "/data/attributes/alias"
              ? ALIAS_FIELD
              : FORM_ERROR;
        next[field] = error.detail;
      });
      setErrors(next);
      return;
    }

    const result = await saveDynamicProviderCredentials({
      providerId: account.providerId,
      secretType,
      secret: validation.secret,
    });
    dispatchProviderFunnel({
      step: PROVIDER_FUNNEL_STEP.ACCOUNT_SUBMITTED,
      providerType,
      via: secretType,
      outcome:
        result.status === "saved"
          ? ACCOUNT_SUBMIT_OUTCOME.SUCCESS
          : ACCOUNT_SUBMIT_OUTCOME.ERROR,
    });
    if (result.status === "saved") {
      useProviderWizardStore.getState().setSecretId(result.secretId);
      useProviderWizardStore.getState().setVia(secretType);
      await connection.check(account.providerId);
    } else if (result.status === "invalid") {
      setErrors(result.errors);
    } else {
      setErrors({ [FORM_ERROR]: saveFailureMessage(result.status) });
    }
  };

  return (
    <form
      id={formId}
      onSubmit={async (event) => {
        event.preventDefault();
        if (inFlight.current) return;
        inFlight.current = true;
        setSaving(true);
        try {
          await submit();
        } catch {
          setErrors({
            [FORM_ERROR]:
              "Could not save the credentials. Check your connection and retry.",
          });
        } finally {
          inFlight.current = false;
          setSaving(false);
        }
      }}
    >
      <fieldset disabled={isBusy} className="flex flex-col gap-4">
        <ConnectionFeedback
          isTesting={connection.isTesting}
          error={connection.error}
          pending={connection.pending}
        />
        {errors[FORM_ERROR] && (
          <StatusAlert variant="error" title="Credentials could not be saved">
            {errors[FORM_ERROR]}
          </StatusAlert>
        )}
        {!locked && (
          <div className="grid gap-4 sm:grid-cols-2">
            <Field>
              <FieldLabel htmlFor={`${formId}-uid`}>
                {uidField.label}
              </FieldLabel>
              <Input
                id={`${formId}-uid`}
                value={uid}
                placeholder={uidField.placeholder}
                aria-invalid={Boolean(errors[UID_FIELD])}
                onChange={(event) => {
                  setUid(event.target.value);
                  clearError(UID_FIELD);
                }}
              />
              {errors[UID_FIELD] && (
                <FieldError>{errors[UID_FIELD]}</FieldError>
              )}
            </Field>
            <Field>
              <FieldLabel htmlFor={`${formId}-alias`}>
                Provider alias (optional)
              </FieldLabel>
              <Input
                id={`${formId}-alias`}
                value={alias}
                placeholder="Enter the provider alias"
                aria-invalid={Boolean(errors[ALIAS_FIELD])}
                onChange={(event) => {
                  setAlias(event.target.value);
                  clearError(ALIAS_FIELD);
                }}
              />
              {errors[ALIAS_FIELD] && (
                <FieldError>{errors[ALIAS_FIELD]}</FieldError>
              )}
            </Field>
          </div>
        )}
        <RegistryCredentialFields
          schema={schema}
          values={values}
          errors={errors}
          onChange={(name, value) => {
            setValues((current) => ({ ...current, [name]: value }));
            clearError(name);
          }}
        />
      </fieldset>
    </form>
  );
}

interface RegistryConnectFormProps extends ConnectFormProps {
  providerType: string;
}

/** Account and credentials of a Registry provider, from its published schema. */
function RegistryConnectContent(props: RegistryConnectFormProps) {
  const { providerType, onUiStateChange, onBusyChange } = props;
  const [schemas, setSchemas] = useState<ProviderSchemasResult | null>(null);
  const [selectedMethod, setSelectedMethod] = useState("");
  const [attempt, setAttempt] = useState(0);
  const [busy, setBusy] = useState(false);
  // The method picker locks with the form; the step hears the same flag.
  useEffect(() => {
    onBusyChange(busy);
  }, [busy, onBusyChange]);
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
    schemas?.status === "success"
      ? listCredentialMethods(schemas.secretTypes)
      : [];
  const method = methods.find(({ id }) => id === selectedMethod) ?? methods[0];
  const schema = method?.schema ?? null;
  useEffect(() => {
    if (!schema)
      onUiStateChange({
        showBack: true,
        showAction: false,
        actionLabel: props.submitLabel,
        actionDisabled: true,
        isLoading: false,
      });
  }, [schema, onUiStateChange, props.submitLabel]);

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

  const error = credentialFormError(
    schemas.status === "success" && methods.length === 0
      ? "not_found"
      : schemas.status,
  );

  return (
    <div className="flex flex-col gap-6">
      {methods.length > 1 && (
        <Field>
          <FieldLabel htmlFor="registry-auth-method">
            Authentication method
          </FieldLabel>
          <Select
            value={method?.id}
            disabled={busy}
            onValueChange={setSelectedMethod}
          >
            <SelectTrigger id="registry-auth-method">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              {methods.map(({ id, label }) => (
                <SelectItem key={id} value={id}>
                  {label}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        </Field>
      )}
      {method && schema ? (
        <RegistryCredentialForm
          key={`${method.id}/${attempt}`}
          {...props}
          secretType={method.secretType}
          schema={schema}
          onBusyChange={setBusy}
        />
      ) : (
        <div className="space-y-4">
          <StatusAlert variant="error" title={error.title}>
            {error.description}
          </StatusAlert>
          <div className="flex flex-wrap gap-3">
            <Button
              type="button"
              variant="outline"
              onClick={() => setAttempt((value) => value + 1)}
            >
              <RotateCcw aria-hidden />
              Try again
            </Button>
            <Button variant="link" asChild>
              <Link href="/registry">Open Registry</Link>
            </Button>
          </div>
        </div>
      )}
    </div>
  );
}

export function RegistryConnectForm(props: RegistryConnectFormProps) {
  return <RegistryConnectContent key={props.providerType} {...props} />;
}
