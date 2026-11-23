import { MetaDataProps } from "@/types";
import { Severity } from "@/types/components";
import { FindingTriageStatus } from "@/types/findings-triage";
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

/** What walking the path buys the attacker. */
export const ISSUE_OUTCOME_LABEL = {
  data_exposure: "Data exposure",
  privilege_escalation: "Privilege escalation",
  code_execution: "Code execution",
} as const;

export type IssueOutcome = keyof typeof ISSUE_OUTCOME_LABEL;

/** Where the attacker has to be standing; whether they need a credential is the access leg. */
export const ATTACKER_START_LABEL = {
  internet: "The internet",
  authenticated_principal: "Any signed-in identity",
  credential_leak: "A leaked credential",
  foothold: "A foothold on a host",
  external_user: "An outside user",
} as const;

export type AttackerStart = keyof typeof ATTACKER_START_LABEL;

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
  /** Blank on the hygiene and unmodelled issues, which are not one path. */
  outcome: IssueOutcome | "";
  attacker_start: AttackerStart | "";
  legs: Record<LegName, LegAssessment>;
  fix: string;
  findings_count: number;
  /** The decision on the path, kept per account and pattern across scans. */
  triage_status: FindingTriageStatus;
  notes_count: number;
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
  uid: string;
  checkId: string;
  checkTitle: string;
  severity: Severity;
  /** The finding's own triage, which stays where it lives. */
  triageStatus: FindingTriageStatus;
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

/** One note on an issue's triage, newest first. */
export interface IssueTriageNote {
  id: string;
  body: string;
  insertedAt: string;
  author?: string;
}
