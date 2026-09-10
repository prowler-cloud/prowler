export interface ScanConfigurationAttributes {
  inserted_at: string;
  updated_at: string;
  name: string;
  configuration: string | Record<string, unknown>;
  providers: string[];
}

export interface ScanConfigurationData {
  type: "scan-configurations";
  id: string;
  attributes: ScanConfigurationAttributes;
}

export const SCAN_CONFIGURATION_LIST_STATUS = {
  AVAILABLE: "available",
  UNAVAILABLE: "unavailable",
} as const;

export type ScanConfigurationListStatus =
  (typeof SCAN_CONFIGURATION_LIST_STATUS)[keyof typeof SCAN_CONFIGURATION_LIST_STATUS];

export interface ScanConfigurationListState {
  status: ScanConfigurationListStatus;
  data: ScanConfigurationData[];
}

export interface ScanConfigurationListResponse {
  data: ScanConfigurationData[];
}

export interface ScanConfigurationErrors {
  name?: string;
  configuration?: string;
  provider_ids?: string;
  general?: string;
}

export interface ScanConfigurationRequestAttributes {
  name: string;
  configuration: Record<string, unknown>;
  provider_ids: string[];
}

export interface ScanConfigurationRequestData {
  type: "scan-configurations";
  id?: string;
  attributes: ScanConfigurationRequestAttributes;
}

export interface ScanConfigurationRequestBody {
  data: ScanConfigurationRequestData;
}

export type ScanConfigurationActionState = {
  errors?: ScanConfigurationErrors;
  success?: string;
  data?: ScanConfigurationData;
} | null;

export interface DeleteScanConfigurationErrors {
  general?: string;
}

export type DeleteScanConfigurationActionState = {
  errors?: DeleteScanConfigurationErrors;
  success?: string;
} | null;
