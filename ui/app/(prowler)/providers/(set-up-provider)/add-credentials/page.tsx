import React from "react";

import {
  AddViaCredentialsForm,
  AddViaRoleForm,
} from "@/components/providers/workflow/forms";
import { AddViaServiceAccountForm } from "@/components/providers/workflow/forms/select-credentials-type/gcp";
import {
  getProviderFormType,
  getSelectorComponentKey,
  PROVIDER_SELECTOR_COMPONENTS,
} from "@/lib/provider-helpers";
import { ProviderType } from "@/types/providers";

interface Props {
  searchParams: Promise<{ type: ProviderType; id: string; via?: string }>;
}

// Form type components mapping
const FORM_COMPONENTS = {
  credentials: AddViaCredentialsForm,
  role: AddViaRoleForm,
  "service-account": AddViaServiceAccountForm,
} as const;

type FormType = keyof typeof FORM_COMPONENTS;

export default async function AddCredentialsPage({ searchParams }: Props) {
  const resolvedSearchParams = await searchParams;
  const { type: providerType, via } = resolvedSearchParams;
  const formType = getProviderFormType(providerType, via);

  // Handle selector form type
  if (formType === "selector") {
    const componentKey = getSelectorComponentKey(providerType);
    if (!componentKey) return null;

    const SelectorComponent = PROVIDER_SELECTOR_COMPONENTS[componentKey];
    return <SelectorComponent initialVia={via} />;
  }

  // Handle other form types
  const FormComponent = FORM_COMPONENTS[formType as FormType];
  if (!FormComponent) return null;

  return <FormComponent searchParams={resolvedSearchParams} />;
}
