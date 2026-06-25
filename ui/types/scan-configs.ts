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

export interface ScanConfigRequestBody {
  data: {
    type: "scan-configs";
    id?: string;
    attributes: {
      name: string;
      configuration: Record<string, unknown>;
      provider_ids: string[];
    };
  };
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
