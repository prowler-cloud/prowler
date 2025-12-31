"use server";

import { revalidatePath } from "next/cache";
import { z } from "zod";

import { apiBaseUrl, getAuthHeaders, getErrorMessage } from "@/lib";
import { handleApiError } from "@/lib/server-actions-helper";

import type {
  ImportScanResult,
  ScanImportApiErrorResponse,
  ScanImportApiResponse,
} from "@/components/scans/scan-import/types";
import {
  ACCEPTED_MIME_TYPES,
  MAX_IMPORT_FILE_SIZE,
} from "@/components/scans/scan-import/types";

/**
 * Zod schema for validating scan import form data.
 */
const importScanSchema = z.object({
  file: z
    .instanceof(File)
    .refine((file: File) => file.size > 0, {
      message: "File is required",
    })
    .refine((file: File) => file.size <= MAX_IMPORT_FILE_SIZE, {
      message: `File size exceeds maximum of ${MAX_IMPORT_FILE_SIZE / (1024 * 1024)}MB`,
    })
    .refine(
      (file: File) => {
        const mimeType = file.type || "";
        const fileName = file.name.toLowerCase();
        // Check MIME type or file extension
        return (
          ACCEPTED_MIME_TYPES.includes(mimeType as (typeof ACCEPTED_MIME_TYPES)[number]) ||
          fileName.endsWith(".json") ||
          fileName.endsWith(".csv")
        );
      },
      {
        message: "File must be JSON or CSV format",
      }
    ),
  providerId: z.string().uuid().optional().or(z.literal("")),
  createProvider: z.coerce.boolean().default(true),
});

/**
 * Type for the import scan action result.
 */
export type ImportScanActionResult =
  | { success: true; data: ImportScanResult }
  | { success: false; error: string; errors?: Record<string, string> };

/**
 * Server action to import Prowler CLI scan results.
 *
 * Accepts a FormData object containing:
 * - file: The scan results file (JSON/OCSF or CSV format)
 * - providerId: (optional) UUID of existing provider to associate
 * - createProvider: (optional) Whether to create provider if not found (default: true)
 *
 * @param formData - FormData containing the import parameters
 * @returns Promise with the import result or error
 */
export async function importScan(
  formData: FormData
): Promise<ImportScanActionResult> {
  try {
    // Extract form data
    const file = formData.get("file") as File | null;
    const providerId = formData.get("providerId") as string | null;
    const createProvider = formData.get("createProvider") as string | null;

    // Validate form data
    const validationResult = importScanSchema.safeParse({
      file,
      providerId: providerId || undefined,
      createProvider: createProvider !== "false",
    });

    if (!validationResult.success) {
      const fieldErrors = validationResult.error.flatten().fieldErrors;
      return {
        success: false,
        error: "Validation failed",
        errors: {
          file: fieldErrors.file?.[0] || "",
          providerId: fieldErrors.providerId?.[0] || "",
          createProvider: fieldErrors.createProvider?.[0] || "",
        },
      };
    }

    const validatedData = validationResult.data;

    // Get auth headers (without Content-Type for multipart)
    const headers = await getAuthHeaders({ contentType: false });

    // Build multipart form data for API request
    const apiFormData = new FormData();
    apiFormData.append("file", validatedData.file);

    if (validatedData.providerId) {
      apiFormData.append("provider_id", validatedData.providerId);
    }

    apiFormData.append(
      "create_provider",
      String(validatedData.createProvider)
    );

    // Make API request
    const url = new URL(`${apiBaseUrl}/scans/import`);
    const response = await fetch(url.toString(), {
      method: "POST",
      headers,
      body: apiFormData,
    });

    // Handle response
    if (!response.ok) {
      const errorData = (await response.json()) as ScanImportApiErrorResponse;
      const firstError = errorData.errors?.[0];

      return {
        success: false,
        error:
          firstError?.detail ||
          firstError?.title ||
          `Import failed with status ${response.status}`,
      };
    }

    const responseData = (await response.json()) as ScanImportApiResponse;
    const attributes = responseData.data.attributes;

    // Revalidate scans page to show the new scan
    revalidatePath("/scans");

    return {
      success: true,
      data: {
        scanId: attributes.scan_id,
        providerId: attributes.provider_id,
        findingsCount: attributes.findings_count,
        resourcesCount: attributes.resources_count,
        status: attributes.status,
        providerCreated: attributes.provider_created,
        warnings: attributes.warnings,
      },
    };
  } catch (error) {
    console.error("Error importing scan:", error);
    const apiError = handleApiError(error);
    return {
      success: false,
      error: apiError.error || getErrorMessage(error),
    };
  }
}
