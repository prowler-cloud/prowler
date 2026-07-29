import type { FC } from "react";

import {
  AWSProviderBadge,
  GCPProviderBadge,
} from "@/components/icons/providers-badge";
import { getCandidateNoun } from "@/lib/organizations";
import type { IconSvgProps } from "@/types/components";
import { ORGANIZATION_TYPE, OrgFlowType } from "@/types/organizations";

/**
 * Component-side organization vocabulary. The words themselves come from the
 * shared terminology table (`lib/organizations`), so wizard copy and the
 * providers table cannot drift; this module adds only what the wizard needs on
 * top — a capitalized plural for headings and the badge to render.
 */
export interface OrgCandidateNoun {
  singular: string;
  plural: string;
  /** Capitalized plural for headings (e.g. "Accounts Connected!"). */
  Plural: string;
}

/**
 * User-facing noun for a discovered candidate: GCP flows say "project(s)" where
 * AWS flows say "account(s)" (see ui-terminology spec).
 */
export function getOrgCandidateNoun(orgType: OrgFlowType): OrgCandidateNoun {
  const { singular, plural } = getCandidateNoun(orgType);

  return {
    singular,
    plural,
    Plural: `${plural.charAt(0).toUpperCase()}${plural.slice(1)}`,
  };
}

// Typed `satisfies Record<OrgFlowType, …>`, so an organization type that gains
// an onboarding flow is a compile error until it brings its own badge — it can
// never silently render the AWS one.
const ORG_PROVIDER_BADGE = {
  [ORGANIZATION_TYPE.AWS]: AWSProviderBadge,
  [ORGANIZATION_TYPE.GCP]: GCPProviderBadge,
} as const satisfies Record<OrgFlowType, FC<IconSvgProps>>;

export function getOrgProviderBadge(orgType: OrgFlowType): FC<IconSvgProps> {
  return ORG_PROVIDER_BADGE[orgType];
}
