/**
 * Organization vocabulary, keyed by organization type and node kind.
 *
 * Every hierarchy surface (providers table, row actions, deletion dialogs,
 * onboarding copy) reads its wording from here instead of branching on a
 * per-provider boolean. The table is typed `satisfies Record<OrganizationType,
 * …>`, so adding an organization type is a compile error until its vocabulary
 * exists — a new type can never silently inherit AWS wording.
 */

import {
  NODE_KIND,
  NodeKind,
  ORGANIZATION_TYPE,
  OrganizationType,
} from "@/types/organizations";

interface CandidateNoun {
  singular: string;
  plural: string;
}

interface OrgTypeTerminology {
  /** Hierarchy container label, used when a node carries no `kind`. */
  containerLabel: string;
  /** Where the provider-side organization/node name comes from. */
  nameSourceLabel: string;
  /** What a discovered candidate is called in the onboarding flow. */
  candidateNoun: CandidateNoun;
}

const ORGANIZATION_TERMINOLOGY = {
  [ORGANIZATION_TYPE.AWS]: {
    containerLabel: "Organizational Unit",
    nameSourceLabel: "AWS",
    candidateNoun: { singular: "account", plural: "accounts" },
  },
  [ORGANIZATION_TYPE.AZURE]: {
    containerLabel: "Management Group",
    nameSourceLabel: "Azure",
    candidateNoun: { singular: "subscription", plural: "subscriptions" },
  },
  [ORGANIZATION_TYPE.GCP]: {
    containerLabel: "Folder",
    nameSourceLabel: "Google Cloud",
    candidateNoun: { singular: "project", plural: "projects" },
  },
} as const satisfies Record<OrganizationType, OrgTypeTerminology>;

const NODE_KIND_LABEL = {
  [NODE_KIND.ORGANIZATIONAL_UNIT]: "Organizational Unit",
  [NODE_KIND.FOLDER]: "Folder",
  [NODE_KIND.MANAGEMENT_GROUP]: "Management Group",
} as const satisfies Record<NodeKind, string>;

const NODE_KINDS: readonly string[] = Object.values(NODE_KIND);

/**
 * The organization-type enum mirrors a server-side one, so a type this build
 * doesn't know about can still arrive on the wire. Rendering neutral wording
 * beats crashing a table cell — or claiming AWS.
 */
const NEUTRAL_TERMINOLOGY: OrgTypeTerminology = {
  containerLabel: "Group",
  nameSourceLabel: "the cloud provider",
  candidateNoun: { singular: "account", plural: "accounts" },
};

const ORGANIZATION_TYPES: readonly string[] = Object.values(ORGANIZATION_TYPE);

// Membership check, not a `??` on the lookup: the tables are object literals, so
// an inherited key ("toString") would resolve to a truthy non-string.
function terminologyFor(orgType: OrganizationType): OrgTypeTerminology {
  return ORGANIZATION_TYPES.includes(orgType)
    ? ORGANIZATION_TERMINOLOGY[orgType]
    : NEUTRAL_TERMINOLOGY;
}

/**
 * Container label for a hierarchy node. `kind` decides when present (canonical
 * contract); the organization type is the fallback. Never derived from ID
 * prefixes.
 */
export function getNodeLabel(
  orgType: OrganizationType,
  kind?: NodeKind,
): string {
  // `kind` is typed but unvalidated: node rows pass the wire attribute through.
  const knownKind = toNodeKind(kind);

  return knownKind
    ? NODE_KIND_LABEL[knownKind]
    : terminologyFor(orgType).containerLabel;
}

/** Provider-side source of the organization name (edit-name helper copy). */
export function getNameSourceLabel(orgType: OrganizationType): string {
  return terminologyFor(orgType).nameSourceLabel;
}

/**
 * What discovered candidates are called for this organization type.
 */
export function getCandidateNoun(orgType: OrganizationType): CandidateNoun {
  return terminologyFor(orgType).candidateNoun;
}

/**
 * Narrows a tree item's opaque `kind` string (the generic `TreeDataItem` carries
 * no organization types) to a canonical node kind.
 */
export function toNodeKind(kind?: string): NodeKind | undefined {
  return kind && NODE_KINDS.includes(kind) ? (kind as NodeKind) : undefined;
}
