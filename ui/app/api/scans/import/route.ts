/**
 * API Route for importing scan results.
 *
 * This route handles large file uploads by streaming directly to the backend API,
 * bypassing Next.js server action body size limits for improved reliability
 * with large files up to 1GB.
 *
 * @module app/api/scans/import/route
 */

import { NextRequest, NextResponse } from "next/server";

import { apiBaseUrl, getAuthHeaders } from "@/lib";

/**
 * Route segment config to allow large request bodies.
 * This is required for Next.js 13+ App Router API routes.
 */
export const runtime = "nodejs";
export const dynamic = "force-dynamic";

/**
 * Maximum file size for scan imports (1GB).
 */
const MAX_FILE_SIZE = 1024 * 1024 * 1024;

/**
 * POST handler for scan import.
 *
 * Receives multipart form data containing Prowler CLI scan results (JSON/OCSF or CSV)
 * and forwards it to the Django backend API for processing.
 *
 * This API route approach provides reliable handling for large file uploads up to 1GB,
 * matching the Django backend's `DATA_UPLOAD_MAX_MEMORY_SIZE` limit.
 *
 * @param request - The incoming Next.js request containing multipart form data
 * @returns JSON response with import results or error details
 *
 * @example
 * // Request format (multipart/form-data):
 * // - file: The scan results file (JSON or CSV)
 * // - provider_id: Optional UUID of existing provider
 * // - create_provider: Boolean to create provider if not found (default: true)
 *
 * @example
 * // Success response (201):
 * // {
 * //   "data": {
 * //     "type": "scan-imports",
 * //     "attributes": {
 * //       "scan_id": "uuid",
 * //       "findings_count": 1500,
 * //       "resources_count": 250
 * //     }
 * //   }
 * // }
 */
export async function POST(request: NextRequest) {
  try {
    // Early validation: Check content length before processing to avoid
    // unnecessary memory allocation for oversized requests
    const contentLength = request.headers.get("content-length");
    if (contentLength && parseInt(contentLength, 10) > MAX_FILE_SIZE) {
      return NextResponse.json(
        {
          errors: [
            {
              title: "File too large",
              detail: `File size exceeds maximum of ${MAX_FILE_SIZE / (1024 * 1024 * 1024)}GB`,
              code: "file_too_large",
            },
          ],
        },
        { status: 413 },
      );
    }

    // Parse the multipart form data from the request
    // This includes the file and optional provider configuration
    const formData = await request.formData();

    // Get authentication headers for the backend API call
    // contentType: false allows fetch to set the correct multipart boundary
    const headers = await getAuthHeaders({ contentType: false });

    // Construct the backend API URL and forward the request
    // The Django backend handles parsing, validation, and database operations
    const backendUrl = `${apiBaseUrl}/scans/import`;

    const response = await fetch(backendUrl, {
      method: "POST",
      headers,
      body: formData,
    });

    // Parse and forward the backend response
    // This preserves the JSON:API format from the Django backend
    const data = await response.json();

    // Return with the same status code to preserve error semantics
    // (201 for success, 400 for validation errors, etc.)
    return NextResponse.json(data, { status: response.status });
  } catch (error) {
    // Log the error for debugging and monitoring
    console.error("Scan import API route error:", error);

    // Handle specific error types with appropriate responses
    if (error instanceof Error) {
      // Check for body size exceeded errors from the request parsing
      if (error.message.includes("body exceeded")) {
        return NextResponse.json(
          {
            errors: [
              {
                title: "File too large",
                detail: "The file size exceeds the maximum allowed limit",
                code: "file_too_large",
              },
            ],
          },
          { status: 413 },
        );
      }
    }

    // Generic error response for unexpected failures
    // Returns JSON:API compliant error format
    return NextResponse.json(
      {
        errors: [
          {
            title: "Import failed",
            detail:
              error instanceof Error
                ? error.message
                : "An unexpected error occurred",
            code: "internal_error",
          },
        ],
      },
      { status: 500 },
    );
  }
}
