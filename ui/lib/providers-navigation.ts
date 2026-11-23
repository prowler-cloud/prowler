import {
  WIZARD_OPEN_SOURCE,
  type WizardOpenSource,
} from "@/lib/provider-funnel/provider-funnel-events";

export const ADD_PROVIDER_SEARCH_PARAM = "addProvider";
export const ADD_PROVIDER_SEARCH_VALUE = "true";
export const ADD_PROVIDER_HREF = `/providers?${ADD_PROVIDER_SEARCH_PARAM}=${ADD_PROVIDER_SEARCH_VALUE}`;

// Optional hint telling the providers page which entry point opened the wizard.
export const ADD_PROVIDER_SOURCE_PARAM = "addProviderSource";

export const buildAddProviderHref = (source: WizardOpenSource): string =>
  `${ADD_PROVIDER_HREF}&${ADD_PROVIDER_SOURCE_PARAM}=${source}`;

const WIZARD_OPEN_SOURCES: readonly string[] =
  Object.values(WIZARD_OPEN_SOURCE);

// Unknown or missing hints fall back to a plain URL-driven open.
export const resolveAddProviderSource = (
  value: string | null | undefined,
): WizardOpenSource =>
  value && WIZARD_OPEN_SOURCES.includes(value)
    ? (value as WizardOpenSource)
    : WIZARD_OPEN_SOURCE.URL;
