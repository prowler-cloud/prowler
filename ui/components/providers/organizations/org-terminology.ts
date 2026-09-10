import type { FC } from "react";

import {
  AWSProviderBadge,
  AzureProviderBadge,
  GCPProviderBadge,
} from "@/components/icons/providers-badge";
import { getCandidateNoun } from "@/lib/organizations";
import type { IconSvgProps } from "@/types/components";
import { ORGANIZATION_TYPE, OrgFlowType } from "@/types/organizations";

/**
 * The words come from the shared terminology table (`lib/organizations`), so
 * wizard copy and the providers table cannot drift. This module only adds what
 * the wizard needs on top: a capitalized plural and the badge to render.
 */
export interface OrgCandidateNoun {
  singular: string;
  plural: string;
  /** Capitalized plural for headings (e.g. "Accounts Connected!"). */
  Plural: string;
}

/**
 * User-facing candidate noun: "project(s)" for GCP, "account(s)" for AWS,
 * "subscription(s)" for Azure.
 */
export function getOrgCandidateNoun(orgType: OrgFlowType): OrgCandidateNoun {
  const { singular, plural } = getCandidateNoun(orgType);

  return {
    singular,
    plural,
    Plural: `${plural.charAt(0).toUpperCase()}${plural.slice(1)}`,
  };
}

// `satisfies Record<OrgFlowType, …>`: a new onboarding flow is a compile error
// until it brings its own badge, instead of silently rendering the AWS one.
const ORG_PROVIDER_BADGE = {
  [ORGANIZATION_TYPE.AWS]: AWSProviderBadge,
  [ORGANIZATION_TYPE.AZURE]: AzureProviderBadge,
  [ORGANIZATION_TYPE.GCP]: GCPProviderBadge,
} as const satisfies Record<OrgFlowType, FC<IconSvgProps>>;

export function getOrgProviderBadge(orgType: OrgFlowType): FC<IconSvgProps> {
  return ORG_PROVIDER_BADGE[orgType];
}
