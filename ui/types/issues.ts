import { MetaDataProps } from "@/types";
import { Severity } from "@/types/components";
import { ProviderType } from "@/types/providers";

/** An issue is a group of findings folded along one attack path. */
export const VERDICT = {
  EXPLOITABLE: "exploitable",
  LIKELY: "likely",
  CONDITIONAL: "conditional",
  NOT_EXPLOITABLE: "not_exploitable",
  UNKNOWN: "unknown",
} as const;

export type Verdict = (typeof VERDICT)[keyof typeof VERDICT];

/** The five legs of an attack path, each asked separately. */
export const LEG_NAME = {
  REACHABILITY: "reachability",
  ACCESS: "access",
  TARGET: "target",
  CONTROLS: "controls",
  VERIFICATION: "verification",
} as const;

export type LegName = (typeof LEG_NAME)[keyof typeof LEG_NAME];

export const LEG_STATE = {
  YES: "yes",
  NO: "no",
  PARTIAL: "partial",
  UNKNOWN: "unknown",
} as const;

export type LegState = (typeof LEG_STATE)[keyof typeof LEG_STATE];

export interface LegAssessment {
  state: LegState;
  text: string;
  /** Check ids and resources the leg is drawn from, so a reader can disagree. */
  evidence: string[];
}

export interface IssueAttributes {
  pattern: string;
  cloud: ProviderType;
  account: string;
  title: string;
  verdict: Verdict;
  severity: Severity;
  legs: Record<LegName, LegAssessment>;
  fix: string;
  findings_count: number;
  inserted_at: string;
  updated_at: string;
}

/**
 * Only the detail carries the uid lists: an unmodelled issue can fold tens of
 * thousands of findings, too many to ship with every page of the list.
 */
export interface IssueDetailAttributes extends IssueAttributes {
  finding_uids: string[];
  resource_uids: string[];
}

/** Maximum findings loaded for the graph preview, independently of its resource limit. */
export const ISSUE_FINDINGS_LIMIT = 50;

/** One finding-to-resource association from the issue's own scan. */
export interface IssueFinding {
  id: string;
  checkId: string;
  checkTitle: string;
  severity: Severity;
  resourceUid: string;
}

export const ISSUE_RELATIONSHIP_TYPE = {
  PROVIDERS: "providers",
  SCANS: "scans",
} as const;

export type IssueRelationshipType =
  (typeof ISSUE_RELATIONSHIP_TYPE)[keyof typeof ISSUE_RELATIONSHIP_TYPE];

export interface IssueRelationshipData {
  type: IssueRelationshipType;
  id: string;
}

export interface IssueRelationship {
  data: IssueRelationshipData | null;
}

export interface IssueRelationships {
  provider?: IssueRelationship;
  scan?: IssueRelationship;
}

export interface IssueResource {
  type: "issues";
  id: string;
  attributes: IssueAttributes;
  relationships?: IssueRelationships;
}

export interface IssueDetailResource extends IssueResource {
  attributes: IssueDetailAttributes;
}

export interface IssueResponse {
  data: IssueResource[];
  meta?: MetaDataProps;
}

export interface IssueDetailResponse {
  data: IssueDetailResource;
}

export interface IssuesOverviewAttributes extends Record<Verdict, number> {
  issues: number;
  findings: number;
  actionable: number;
  not_exploitable_findings: number;
}

export interface IssuesOverviewResource {
  type: "issues-overview";
  id?: string;
  attributes: IssuesOverviewAttributes;
}

export interface IssuesOverviewResponse {
  data: IssuesOverviewResource;
}
