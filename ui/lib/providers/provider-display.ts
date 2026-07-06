import { type FC } from "react";

import {
  AlibabaCloudProviderBadge,
  AWSProviderBadge,
  AzureProviderBadge,
  CloudflareProviderBadge,
  GCPProviderBadge,
  GitHubProviderBadge,
  GoogleWorkspaceProviderBadge,
  KS8ProviderBadge,
  M365ProviderBadge,
  MongoDBAtlasProviderBadge,
  OktaProviderBadge,
  OpenStackProviderBadge,
  OracleCloudProviderBadge,
  VercelProviderBadge,
} from "@/components/icons/providers-badge";
import type { IconSvgProps } from "@/types/components";
import { PROVIDER_DISPLAY_NAMES, type ProviderType } from "@/types/providers";

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
  github: GitHubProviderBadge,
  googleworkspace: GoogleWorkspaceProviderBadge,
  okta: OktaProviderBadge,
  cloudflare: CloudflareProviderBadge,
  mongodbatlas: MongoDBAtlasProviderBadge,
  openstack: OpenStackProviderBadge,
  vercel: VercelProviderBadge,
};

/**
 * Labels for providers the SDK's universal compliance templates can declare
 * (e.g. cross-provider CIS Controls) that aren't onboarded as a
 * ``ProviderType`` yet — no icon, account selector, or scan config exists
 * for them, so they only ever reach ``getProviderLabel``'s fallback badge.
 * Real providers must NOT be duplicated here: ``PROVIDER_DISPLAY_NAMES`` in
 * ``@/types/providers`` is the single source of truth for those.
 */
const FALLBACK_ONLY_PROVIDER_LABELS: Record<string, string> = {
  linode: "Linode",
  stackit: "STACKIT",
  nhn: "NHN Cloud",
  scaleway: "Scaleway",
};

/** Resolve a provider label, falling back to an uppercased key. */
export const getProviderLabel = (providerKey: string): string =>
  PROVIDER_DISPLAY_NAMES[providerKey as ProviderType] ??
  FALLBACK_ONLY_PROVIDER_LABELS[providerKey] ??
  providerKey.toUpperCase();

/** Resolve the badge component, returning ``undefined`` when no icon
 *  is registered for the given key (the consumer renders a fallback). */
export const getProviderBadge = (
  providerKey: string,
): FC<IconSvgProps> | undefined => PROVIDER_BADGE_BY_KEY[providerKey];
