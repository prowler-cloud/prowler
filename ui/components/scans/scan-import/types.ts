/**
 * Types for the Scan Import feature.
 *
 * These types define the data structures for importing Prowler CLI scan results
 * (JSON/OCSF and CSV formats) into the Prowler API.
 */

import { ProviderType } from "@/types/providers";

/**
 * Supported file formats for scan import.
 */
export type ImportFileFormat = "json" | "csv";

/**
 * Status of the import operation.
 */
export type ImportStatus =
  | "idle"
  | "uploading"
  | "processing"
  | "completed"
  | "error";

/**
 * Result returned from a successful scan import API call.
 * Matches the ScanImportResponseSerializer from the backend.
 */
export interface ImportScanResult {
  /** UUID of the created scan */
  scanId: string;
  /** UUID of the associated provider */
  providerId: string;
  /** Number of findings imported */
  findingsCount: number;
  /** Number of unique resources imported */
  resourcesCount: number;
  /** Status of the import operation */
  status: string;
  /** Whether a new provider was created during import */
  providerCreated: boolean;
  /** Optional list of warnings encountered during import */
  warnings?: string[];
}

/**
 * Error details returned from a failed scan import.
 */
export interface ImportScanError {
  /** HTTP status code */
  status?: string;
  /** Error code identifier */
  code?: string;
  /** Short error title */
  title: string;
  /** Detailed error message */
  detail: string;
  /** Source location of the error (e.g., field path) */
  source?: {
    pointer?: string;
  };
}

/**
 * Form data for the scan import form.
 */
export interface ScanImportFormData {
  /** The file to upload (JSON or CSV) */
  file: File | null;
  /** Optional UUID of existing provider to associate with the import */
  providerId?: string;
  /** Whether to create a new provider if one is not found */
  createProvider: boolean;
}

/**
 * Props for the scan import dropzone component.
 */
export interface ScanImportDropzoneProps {
  /** Currently selected file */
  file: File | null;
  /** Callback when a file is selected */
  onFileSelect: (file: File | null) => void;
  /** Whether the dropzone is disabled */
  disabled?: boolean;
  /** Accepted file types */
  acceptedTypes?: string[];
  /** Maximum file size in bytes (default: 50MB) */
  maxSize?: number;
}

/**
 * Props for the scan import form component.
 */
export interface ScanImportFormProps {
  /** Callback when form is submitted */
  onSubmit: (data: ScanImportFormData) => void;
  /** Whether the form is currently submitting */
  isSubmitting?: boolean;
  /** Available providers for selection */
  providers?: Array<{
    id: string;
    provider: ProviderType;
    uid: string;
    alias: string;
  }>;
}

/**
 * Processing step identifiers for detailed status display.
 */
export type ProcessingStep =
  | "parsing"
  | "validating"
  | "resolving-provider"
  | "creating-resources"
  | "creating-findings"
  | "finalizing";

/**
 * Processing step information for display.
 */
export interface ProcessingStepInfo {
  /** Current processing step */
  step: ProcessingStep;
  /** Human-readable message for the current step */
  message?: string;
}

/**
 * Props for the scan import progress component.
 */
export interface ScanImportProgressProps {
  /** Current status of the import */
  status: ImportStatus;
  /** Progress percentage (0-100) */
  progress?: number;
  /** Current processing step information */
  processingStep?: ProcessingStepInfo;
  /** Result data on success */
  result?: ImportScanResult;
  /** Error data on failure (single error for backward compatibility) */
  error?: ImportScanError;
  /** Multiple errors from validation failures */
  errors?: ImportScanError[];
  /** Callback to reset/dismiss the progress display */
  onReset?: () => void;
}

/**
 * Props for the main scan import section component.
 */
export interface ScanImportSectionProps {
  /** Callback when import completes successfully */
  onImportComplete?: (scanId: string) => void;
}

/**
 * API response structure for scan import (JSON:API format).
 */
export interface ScanImportApiResponse {
  data: {
    type: "scan-imports";
    id: string;
    attributes: {
      scan_id: string;
      provider_id: string;
      findings_count: number;
      resources_count: number;
      status: string;
      provider_created: boolean;
      warnings?: string[];
    };
  };
  meta?: {
    version: string;
  };
}

/**
 * API error response structure (JSON:API format).
 */
export interface ScanImportApiErrorResponse {
  errors: Array<{
    status?: string;
    code?: string;
    title?: string;
    detail?: string;
    source?: {
      pointer?: string;
    };
  }>;
}

/**
 * Maximum file size for scan import (50MB).
 */
export const MAX_IMPORT_FILE_SIZE = 50 * 1024 * 1024;

/**
 * Accepted file extensions for scan import.
 */
export const ACCEPTED_FILE_EXTENSIONS = [".json", ".csv"] as const;

/**
 * Accepted MIME types for scan import.
 */
export const ACCEPTED_MIME_TYPES = [
  "application/json",
  "text/csv",
  "text/plain",
] as const;
