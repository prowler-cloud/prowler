import { ProviderType } from "./providers";

export interface ScanProps {
  type: "scans";
  id: string;
  attributes: {
    name: string;
    trigger: "scheduled" | "manual";
    state:
      | "available"
      | "scheduled"
      | "executing"
      | "completed"
      | "failed"
      | "cancelled";
    unique_resource_count: number;
    progress: number;
    scanner_args: {
      only_logs?: boolean;
      excluded_checks?: string[];
      aws_retries_max_attempts?: number;
    } | null;
    duration: number;
    started_at: string;
    inserted_at: string;
    completed_at: string;
    scheduled_at: string;
    next_scan_at: string;
  };
  relationships: {
    provider: {
      data: {
        id: string;
        type: "providers";
      };
    };
    task: {
      data: {
        id: string;
        type: "tasks";
      };
    };
  };
  providerInfo?: {
    provider: ProviderType;
    uid: string;
    alias: string;
  };
}
