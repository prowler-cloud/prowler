export interface MuteRuleAttributes {
  inserted_at: string;
  updated_at: string;
  name: string;
  reason: string;
  enabled: boolean;
  finding_uids: string[];
}

export interface MuteRuleRelationships {
  created_by?: {
    data: {
      type: "users";
      id: string;
    } | null;
  };
}

export interface MuteRuleData {
  type: "mute-rules";
  id: string;
  attributes: MuteRuleAttributes;
  relationships?: MuteRuleRelationships;
}

export interface MuteRulesResponse {
  data: MuteRuleData[];
  meta: {
    pagination: {
      page: number;
      pages: number;
      count: number;
    };
  };
  links: {
    first: string;
    last: string;
    next: string | null;
    prev: string | null;
  };
}

export interface MuteRuleResponse {
  data: MuteRuleData;
}

export type MuteRuleActionState = {
  errors?: {
    name?: string;
    reason?: string;
    finding_ids?: string;
    general?: string;
  };
  success?: string;
} | null;

export type DeleteMuteRuleActionState = {
  errors?: {
    general?: string;
  };
  success?: string;
} | null;
