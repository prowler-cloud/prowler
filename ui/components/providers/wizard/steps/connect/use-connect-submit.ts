"use client";

import { useEffect } from "react";
import { FieldValues, UseFormReturn, useFormState } from "react-hook-form";

import { useFormServerErrors } from "@/hooks/use-form-server-errors";
import { PROVIDER_CREDENTIALS_ERROR_MAPPING } from "@/lib/error-mappings";
import { ProviderCredentialFields } from "@/lib/provider-credentials/provider-credential-fields";
import {
  ACCOUNT_SUBMIT_OUTCOME,
  dispatchProviderFunnel,
  PROVIDER_FUNNEL_STEP,
} from "@/lib/provider-funnel/provider-funnel-events";

import {
  connectProviderAccount,
  UID_ERROR_POINTER,
} from "./connect-provider-account";
import type { ConnectFormProps } from "./types";
import {
  resolveConnectActionLabel,
  useConnectionCheck,
} from "./use-connection-check";

const ALIAS_ERROR_POINTER = "/data/attributes/alias";
const UNIQUE_TOGETHER_ERROR_POINTER = "/data/attributes/__all__";

export interface ConnectIdentity {
  uid: string | null;
  /** Undefined keeps the stored alias. */
  alias?: string;
}

interface UseConnectSubmitOptions<T extends FieldValues>
  extends Omit<ConnectFormProps, "formId"> {
  form: UseFormReturn<T>;
  providerType: string;
  method: string | null;
  // The field an account-level API error belongs to for this form.
  accountField: string;
  // Beyond form validity: e.g. the AWS role form needs an account read from the ARN.
  accountResolved?: boolean;
  resolveIdentity: (values: T) => ConnectIdentity;
  extraValues?: Record<string, string>;
}

/** Registers the account, stores its credentials and tests the connection in one submit. */
export function useConnectSubmit<T extends FieldValues>({
  form,
  providerType,
  method,
  accountField,
  accountResolved = true,
  resolveIdentity,
  extraValues,
  locked,
  submitLabel,
  onConnected,
  onBusyChange,
  onUiStateChange,
}: UseConnectSubmitOptions<T>) {
  const { handleServerResponse } = useFormServerErrors(form, {
    ...PROVIDER_CREDENTIALS_ERROR_MAPPING,
    [UID_ERROR_POINTER]: accountField,
    [UNIQUE_TOGETHER_ERROR_POINTER]: accountField,
    [ALIAS_ERROR_POINTER]: ProviderCredentialFields.PROVIDER_ALIAS,
  });
  const connection = useConnectionCheck(onConnected);
  // A hook, not `form.formState.isValid` read inline: the React Compiler keys
  // its memo on the stable `form` object and would freeze a proxy read at false.
  const { isSubmitting, isValid } = useFormState({ control: form.control });
  const canSubmit = isValid && accountResolved;
  const isBusy = isSubmitting || connection.isTesting;
  const hasFailed = connection.error !== null;
  const hasPending = connection.pending !== null;

  // Same contract as every connect form: the wizard footer lives outside the step.
  // Both callbacks must be stable setters, or this effect would loop.
  useEffect(() => {
    onBusyChange(isBusy);
    onUiStateChange({
      showBack: true,
      showAction: true,
      actionLabel: resolveConnectActionLabel({
        submitLabel,
        isTesting: connection.isTesting,
        isSubmitting,
        hasFailed,
        hasPending,
      }),
      actionDisabled: !canSubmit || isBusy,
      isLoading: isBusy,
    });
  }, [
    canSubmit,
    connection.isTesting,
    hasFailed,
    hasPending,
    isBusy,
    isSubmitting,
    onBusyChange,
    onUiStateChange,
    submitLabel,
  ]);

  // A past failure or a still-pending result must not sit above the field the
  // user is already correcting.
  const { clear } = connection;
  useEffect(() => {
    if (!hasFailed && !hasPending) return;
    const subscription = form.watch(() => clear());
    return () => subscription.unsubscribe();
  }, [clear, form, hasFailed, hasPending]);

  const onSubmit = form.handleSubmit(async (values) => {
    connection.clear();
    const identity = resolveIdentity(values);
    const result = await connectProviderAccount({
      providerType,
      method,
      uid: identity.uid,
      alias: identity.alias,
      secretValues: { ...values, ...extraValues },
      locked,
    });
    dispatchProviderFunnel({
      step: PROVIDER_FUNNEL_STEP.ACCOUNT_SUBMITTED,
      providerType,
      via: method ?? "default",
      outcome: result.ok
        ? ACCOUNT_SUBMIT_OUTCOME.SUCCESS
        : ACCOUNT_SUBMIT_OUTCOME.ERROR,
    });
    if (!result.ok) {
      // Maps API pointers onto the form's fields; anything unmapped becomes a toast.
      handleServerResponse({ errors: result.errors });
      return;
    }

    // The account stays registered whatever the test says; resubmitting edits it.
    await connection.check(result.providerId);
  });

  return {
    onSubmit,
    isTesting: connection.isTesting,
    connectionError: connection.error,
    connectionPending: connection.pending,
  };
}
