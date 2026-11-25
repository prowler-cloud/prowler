import type { RequirementStatus } from "@/types/compliance";
import type { ProviderType } from "@/types/providers";
import type { SeverityLevel } from "@/types/severities";

export interface AiResultCounts {
  pass: number;
  fail: number;
  manual: number;
}

export type AiSeverityCounts = Record<SeverityLevel, number>;

/** One provider's gen-ai results inside a layer of the AI stack. */
export interface AiStackProvider extends AiResultCounts {
  type: ProviderType;
  name: string;
  /** What was scanned, such as "2 accounts". */
  scope: string;
  connected: boolean;
}

export interface AiStackLayer {
  id: string;
  name: string;
  description: string;
  providers: AiStackProvider[];
}

export interface AiFrameworkSection extends AiResultCounts {
  /** The section as the framework labels it; empty for requirements without one. */
  id: string;
  /** The section's code in the framework, such as "LLM01". Empty when it has none. */
  code: string;
  name: string;
}

export interface AiFramework {
  id: string;
  shortName: string;
  name: string;
  version: string;
  /** What the framework counts: "requirements", "controls"… */
  unit: string;
  note?: string;
  sections: AiFrameworkSection[];
}

/** One check of a requirement, as the latest scans left it. */
export interface AiRequirementCheck {
  id: string;
  title: string;
  /** "No findings" when the latest scans produced none for it. */
  status: RequirementStatus;
  failedResources: number;
}

/** A requirement of a framework section with the checks that evidence it. */
export interface AiRequirement {
  id: string;
  name: string;
  description: string;
  status: RequirementStatus;
  /** None for a manual requirement. */
  checks: AiRequirementCheck[];
}

export interface AiTopRisk {
  checkId: string;
  title: string;
  severity: SeverityLevel;
  providerName: string;
  /** How much it touches, such as "3 resources". */
  affected: string;
}

export interface AiSecurityOverview extends AiResultCounts {
  severity: AiSeverityCounts;
  layers: AiStackLayer[];
  frameworks: AiFramework[];
  topRisks: AiTopRisk[];
}
