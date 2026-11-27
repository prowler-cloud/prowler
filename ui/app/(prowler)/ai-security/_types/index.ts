import type { ProviderType } from "@/types/providers";
import type { SeverityLevel } from "@/types/severities";

export interface AiResultCounts {
  pass: number;
  fail: number;
  manual: number;
  /** Failed findings that were not in the previous scan. */
  newFail: number;
}

export type AiSeverityCounts = Record<SeverityLevel, number>;

/** One provider's gen-ai results inside a layer of the AI stack. */
export interface AiStackProvider extends AiResultCounts {
  type: ProviderType;
  name: string;
  /** What was scanned, such as "2 accounts". */
  scope: string;
  connected: boolean;
  /** Has a completed scan; without one there are no results to show. */
  scanned: boolean;
  /** Its failed findings by severity. */
  severity: AiSeverityCounts;
  /** The services with failed findings. */
  services: string[];
}

export interface AiStackLayer {
  id: string;
  name: string;
  description: string;
  providers: AiStackProvider[];
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
  topRisks: AiTopRisk[];
}
