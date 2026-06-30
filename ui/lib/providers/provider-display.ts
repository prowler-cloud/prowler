import { type FC } from "react";

import {
  AlibabaCloudProviderBadge,
  AWSProviderBadge,
  AzureProviderBadge,
  GCPProviderBadge,
  KS8ProviderBadge,
  M365ProviderBadge,
  OracleCloudProviderBadge,
} from "@/components/icons/providers-badge";
import type { IconSvgProps } from "@/types/components";

/**
 * Single source of truth for provider display metadata. Kept in
 * ``ui/lib/providers`` (not ``ui/lib/compliance``) so non-compliance
 * surfaces (settings, scan list, finding drawer) can adopt it without
 * fanning out duplicates the way the compliance accordion did.
 *
 * Keys are the lowercase provider strings the API emits in
 * ``provider_type`` and ``providers[*]``. New providers must be added
 * here once and consumers will pick them up automatically.
 */
export const PROVIDER_BADGE_BY_KEY: Record<string, FC<IconSvgProps>> = {
  aws: AWSProviderBadge,
  azure: AzureProviderBadge,
  gcp: GCPProviderBadge,
  alibabacloud: AlibabaCloudProviderBadge,
  oraclecloud: OracleCloudProviderBadge,
  kubernetes: KS8ProviderBadge,
  m365: M365ProviderBadge,
};

export const PROVIDER_LABEL_BY_KEY: Record<string, string> = {
  aws: "AWS",
  azure: "Azure",
  gcp: "GCP",
  alibabacloud: "Alibaba Cloud",
  oraclecloud: "Oracle Cloud",
  kubernetes: "Kubernetes",
  m365: "Microsoft 365",
};

/** Resolve a provider label, falling back to an uppercased key. */
export const getProviderLabel = (providerKey: string): string =>
  PROVIDER_LABEL_BY_KEY[providerKey] ?? providerKey.toUpperCase();

/** Resolve the badge component, returning ``undefined`` when no icon
 *  is registered for the given key (the consumer renders a fallback). */
export const getProviderBadge = (
  providerKey: string,
): FC<IconSvgProps> | undefined => PROVIDER_BADGE_BY_KEY[providerKey];
