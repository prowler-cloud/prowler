"use client";

import { useEffect } from "react";
import { FieldValues, UseFormReturn, useWatch } from "react-hook-form";

import { useProviderWizardStore } from "@/store/provider-wizard/store";
import type { ConnectDraftValues } from "@/types/provider-wizard";

const DEFAULT_METHOD_KEY = "default";

export const draftMethodKey = (method: string | null) =>
  method ?? DEFAULT_METHOD_KEY;

/** What was typed for this provider and method earlier in the same wizard. */
export const readDraftValues = (
  providerType: string,
  method: string | null,
): ConnectDraftValues | undefined => {
  const draft = useProviderWizardStore.getState().connectDraft;
  if (draft?.providerType !== providerType) return undefined;
  return draft.values[draftMethodKey(method)];
};

// What the user typed survives the step unmounting (organizations tab, a step
// back from the launch step) until the wizard closes.
export function useDraftValues<T extends FieldValues>(
  form: UseFormReturn<T>,
  providerType: string,
  method: string | null,
) {
  const values = useWatch({ control: form.control });
  useEffect(() => {
    const store = useProviderWizardStore.getState();
    const current =
      store.connectDraft?.providerType === providerType
        ? store.connectDraft.values
        : {};
    store.setConnectDraft(providerType, {
      values: {
        ...current,
        [draftMethodKey(method)]: values as ConnectDraftValues,
      },
    });
  }, [method, providerType, values]);
}
