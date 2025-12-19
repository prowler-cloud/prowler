// Mute Rules Types
// Corresponds to the /mute-rules endpoint

// Base relationship data structure
export interface RelationshipData {
  type: "users";
  id: string;
}

export interface CreatedByRelationship {
  data: RelationshipData | null;
}

export interface MuteRuleRelationships {
  created_by?: CreatedByRelationship;
}

export interface MuteRuleAttributes {
  inserted_at: string;
  updated_at: string;
  name: string;
  reason: string;
  enabled: boolean;
  finding_uids: string[];
}

export interface MuteRuleData {
  type: "mute-rules";
  id: string;
  attributes: MuteRuleAttributes;
  relationships?: MuteRuleRelationships;
}

// Response pagination and links
export interface MuteRulesPagination {
  page: number;
  pages: number;
  count: number;
}

export interface MuteRulesMeta {
  pagination: MuteRulesPagination;
}

export interface MuteRulesLinks {
  first: string;
  last: string;
  next: string | null;
  prev: string | null;
}

export interface MuteRulesResponse {
  data: MuteRuleData[];
  meta: MuteRulesMeta;
  links: MuteRulesLinks;
}

export interface MuteRuleResponse {
  data: MuteRuleData;
}

// Action state types
export interface MuteRuleActionErrors {
  name?: string;
  reason?: string;
  finding_ids?: string;
  general?: string;
}

export type MuteRuleActionState = {
  errors?: MuteRuleActionErrors;
  success?: string;
} | null;

export interface DeleteMuteRuleActionErrors {
  general?: string;
}

export type DeleteMuteRuleActionState = {
  errors?: DeleteMuteRuleActionErrors;
  success?: string;
} | null;
