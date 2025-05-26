// Status types
export type RequirementStatus = "PASS" | "FAIL" | "MANUAL";

// Core interfaces - simple and direct
export interface Requirement {
  name: string;
  description: string;
  status: RequirementStatus;
  type: string;
  pass: number;
  fail: number;
  manual: number;
  check_ids: string[];
}

export interface Control {
  label: string;
  type: string;
  pass: number;
  fail: number;
  manual: number;
  requirements: Requirement[];
}

export interface Category {
  name: string;
  pass: number;
  fail: number;
  manual: number;
  controls: Control[];
}

export interface Framework {
  name: string;
  pass: number;
  fail: number;
  manual: number;
  categories: Category[];
}

export type MappedComplianceData = Framework[];

export interface FailedSection {
  name: string;
  total: number;
  types: { [key: string]: number };
}

export interface RequirementsTotals {
  pass: number;
  fail: number;
  manual: number;
}
