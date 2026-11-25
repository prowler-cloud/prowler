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
