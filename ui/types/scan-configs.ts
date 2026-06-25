export interface ScanConfigAttributes {
  inserted_at: string;
  updated_at: string;
  name: string;
  configuration: string | Record<string, unknown>;
  providers: string[];
}

export interface ScanConfigData {
  type: "scan-configs";
  id: string;
  attributes: ScanConfigAttributes;
}

export interface ScanConfigListResponse {
  data: ScanConfigData[];
}

export interface ScanConfigErrors {
  name?: string;
  configuration?: string;
  provider_ids?: string;
  general?: string;
}

export interface ScanConfigRequestAttributes {
  name: string;
  configuration: Record<string, unknown>;
  provider_ids: string[];
}

export interface ScanConfigRequestData {
  type: "scan-configs";
  id?: string;
  attributes: ScanConfigRequestAttributes;
}

export interface ScanConfigRequestBody {
  data: ScanConfigRequestData;
}

export type ScanConfigActionState = {
  errors?: ScanConfigErrors;
  success?: string;
  data?: ScanConfigData;
} | null;

export type DeleteScanConfigActionState = {
  errors?: {
    general?: string;
  };
  success?: string;
} | null;
