import {
  getComplianceCsv,
  getCompliancePdfReport,
  getExportsZip,
} from "@/actions/scans";
import { getTask } from "@/actions/task";
import { auth } from "@/auth.config";
import { useToast } from "@/components/ui";
import {
  COMPLIANCE_REPORT_DISPLAY_NAMES,
  type ComplianceReportType,
} from "@/lib/compliance/compliance-report-types";
import { AuthSocialProvider, MetaDataProps, PermissionInfo } from "@/types";

export const baseUrl = process.env.AUTH_URL || "http://localhost:3000";
export const apiBaseUrl = process.env.NEXT_PUBLIC_API_BASE_URL;

/**
 * Extracts a form value from a FormData object
 * @param formData - The FormData object to extract from
 * @param field - The name of the field to extract
 * @returns The value of the field
 */
export const getFormValue = (formData: FormData, field: string) =>
  formData.get(field);

/**
 * Filters out empty values from an object
 * @param obj - Object to filter
 * @returns New object with empty values removed
 * Avoids sending empty values to the API
 */
export function filterEmptyValues(
  obj: Record<string, any>,
): Record<string, any> {
  return Object.fromEntries(
    Object.entries(obj).filter(([_, value]) => {
      // Keep number 0 and boolean false as they are valid values
      if (value === 0 || value === false) return true;

      // Filter out null, undefined, empty strings, and empty arrays
      if (value === null || value === undefined) return false;
      if (typeof value === "string" && value.trim() === "") return false;
      if (Array.isArray(value) && value.length === 0) return false;

      return true;
    }),
  );
}

/**
 * Returns the authentication headers for API requests
 * @param options - Optional configuration options
 * @returns Authentication headers with Accept and Authorization
 */
export const getAuthHeaders = async (options?: { contentType?: boolean }) => {
  const session = await auth();

  const headers: Record<string, string> = {
    Accept: "application/vnd.api+json",
    Authorization: `Bearer ${session?.accessToken}`,
  };

  if (options?.contentType) {
    headers["Content-Type"] = "application/vnd.api+json";
  }

  return headers;
};

export const getAuthUrl = (provider: AuthSocialProvider) => {
  const config = {
    google: {
      baseUrl: "https://accounts.google.com/o/oauth2/v2/auth",
      params: {
        redirect_uri: process.env.SOCIAL_GOOGLE_OAUTH_CALLBACK_URL,
        prompt: "consent",
        response_type: "code",
        client_id: process.env.SOCIAL_GOOGLE_OAUTH_CLIENT_ID,
        scope: "openid email profile",
        access_type: "offline",
      },
    },
    github: {
      baseUrl: "https://github.com/login/oauth/authorize",
      params: {
        client_id: process.env.SOCIAL_GITHUB_OAUTH_CLIENT_ID,
        redirect_uri: process.env.SOCIAL_GITHUB_OAUTH_CALLBACK_URL,
        scope: "user:email",
      },
    },
  };

  const { baseUrl, params } = config[provider];
  const url = new URL(baseUrl);

  Object.entries(params).forEach(([key, value]) => {
    url.searchParams.set(key, value || "");
  });

  return url.toString();
};

export const downloadScanZip = async (
  scanId: string,
  toast: ReturnType<typeof useToast>["toast"],
) => {
  const result = await getExportsZip(scanId);

  if (result?.pending) {
    toast({
      title: "The report is still being generated",
      description: "Please try again in a few minutes.",
    });
    return;
  }

  if (result?.success && result.data) {
    const binaryString = window.atob(result.data);
    const bytes = new Uint8Array(binaryString.length);
    for (let i = 0; i < binaryString.length; i++) {
      bytes[i] = binaryString.charCodeAt(i);
    }

    const blob = new Blob([bytes], { type: "application/zip" });
    const url = window.URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = result.filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    window.URL.revokeObjectURL(url);

    toast({
      title: "Download Complete",
      description: "Your scan report has been downloaded successfully.",
    });
  } else {
    toast({
      variant: "destructive",
      title: "Download Failed",
      description: result?.error || "An unknown error occurred.",
    });
  }
};

/**
 * Generic function to download a file from base64 data
 */
const downloadFile = async (
  result: any,
  outputType: string,
  successMessage: string,
  toast: ReturnType<typeof useToast>["toast"],
): Promise<void> => {
  if (result?.pending) {
    toast({
      title: "The report is still being generated",
      description: "Please try again in a few minutes.",
    });
    return;
  }

  if (result?.success && result.data) {
    try {
      const binaryString = window.atob(result.data);
      const bytes = new Uint8Array(binaryString.length);
      for (let i = 0; i < binaryString.length; i++) {
        bytes[i] = binaryString.charCodeAt(i);
      }

      const blob = new Blob([bytes], { type: outputType });
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = result.filename;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      window.URL.revokeObjectURL(url);

      toast({
        title: "Download Complete",
        description: successMessage,
      });
    } catch (_error) {
      toast({
        variant: "destructive",
        title: "Download Failed",
        description: "An error occurred while processing the file.",
      });
    }
    return;
  }

  if (result?.error) {
    toast({
      variant: "destructive",
      title: "Download Failed",
      description: result.error,
    });
    return;
  }

  // Unexpected case
  toast({
    variant: "destructive",
    title: "Download Failed",
    description: "Unexpected response. Please try again later.",
  });
};

export const downloadComplianceCsv = async (
  scanId: string,
  complianceId: string,
  toast: ReturnType<typeof useToast>["toast"],
): Promise<void> => {
  const result = await getComplianceCsv(scanId, complianceId);
  await downloadFile(
    result,
    "text/csv",
    "The compliance report has been downloaded successfully.",
    toast,
  );
};

/**
 * Generic function to download a compliance PDF report (ThreatScore, ENS, etc.)
 * @param scanId - The scan ID
 * @param reportType - Type of report (from COMPLIANCE_REPORT_TYPES)
 * @param toast - Toast notification function
 */
export const downloadComplianceReportPdf = async (
  scanId: string,
  reportType: ComplianceReportType,
  toast: ReturnType<typeof useToast>["toast"],
): Promise<void> => {
  const result = await getCompliancePdfReport(scanId, reportType);
  const reportName = COMPLIANCE_REPORT_DISPLAY_NAMES[reportType];
  await downloadFile(
    result,
    "application/pdf",
    `The ${reportName} PDF report has been downloaded successfully.`,
    toast,
  );
};

export const isGoogleOAuthEnabled =
  !!process.env.SOCIAL_GOOGLE_OAUTH_CLIENT_ID &&
  !!process.env.SOCIAL_GOOGLE_OAUTH_CLIENT_SECRET;

export const isGithubOAuthEnabled =
  !!process.env.SOCIAL_GITHUB_OAUTH_CLIENT_ID &&
  !!process.env.SOCIAL_GITHUB_OAUTH_CLIENT_SECRET;

export const checkTaskStatus = async (
  taskId: string,
  maxRetries: number = 20,
  retryDelay: number = 1500,
): Promise<{ completed: boolean; error?: string }> => {
  for (let attempt = 0; attempt < maxRetries; attempt++) {
    const task = await getTask(taskId);

    if (task.error) {
      console.error(`Error retrieving task: ${task.error}`);
      return { completed: false, error: task.error };
    }

    const state = task.data.attributes.state;

    switch (state) {
      case "completed":
        return { completed: true };
      case "failed":
        return { completed: false, error: task.data.attributes.result.error };
      case "available":
      case "scheduled":
      case "executing":
        // Continue waiting if the task is still in progress
        await new Promise((resolve) => setTimeout(resolve, retryDelay));
        break;
      default:
        return { completed: false, error: "Unexpected task state" };
    }
  }

  return { completed: false, error: "Max retries exceeded" };
};

export const wait = (ms: number) =>
  new Promise((resolve) => setTimeout(resolve, ms));

// Helper function to create dictionaries by type
export function createDict(type: string, data: any) {
  const includedField = data?.included?.filter(
    (item: { type: string }) => item.type === type,
  );

  if (!includedField || includedField.length === 0) {
    return {};
  }

  return Object.fromEntries(
    includedField.map((item: { id: string }) => [item.id, item]),
  );
}

export const parseStringify = (value: any) => JSON.parse(JSON.stringify(value));

export const convertFileToUrl = (file: File) => URL.createObjectURL(file);

export const getPaginationInfo = (metadata: MetaDataProps) => {
  const currentPage = metadata?.pagination.page ?? "1";
  const totalPages = metadata?.pagination.pages;
  const totalEntries = metadata?.pagination.count;
  const itemsPerPageOptions = metadata?.pagination.itemsPerPage ?? [
    10, 20, 30, 50, 100,
  ];

  return { currentPage, totalPages, totalEntries, itemsPerPageOptions };
};

export function encryptKey(passkey: string) {
  return btoa(passkey);
}

export function decryptKey(passkey: string) {
  return atob(passkey);
}

export const getErrorMessage = (error: unknown): string => {
  if (error instanceof Error) {
    return error.message;
  } else if (error && typeof error === "object" && "message" in error) {
    return String(error.message);
  } else if (typeof error === "string") {
    return error;
  } else {
    return "Oops! Something went wrong.";
  }
};

export const permissionFormFields: PermissionInfo[] = [
  {
    field: "manage_users",
    label: "Invite and Manage Users",
    description: "Allows inviting new users and managing existing user details",
  },
  {
    field: "manage_account",
    label: "Manage Account",
    description: "Provides access to account settings and RBAC configuration",
  },
  {
    field: "unlimited_visibility",
    label: "Unlimited Visibility",
    description:
      "Provides complete visibility across all the providers and its related resources",
  },
  {
    field: "manage_providers",
    label: "Manage Cloud Providers",
    description:
      "Allows configuration and management of cloud provider connections",
  },
  {
    field: "manage_integrations",
    label: "Manage Integrations",
    description:
      "Allows configuration and management of third-party integrations",
  },
  {
    field: "manage_scans",
    label: "Manage Scans",
    description: "Allows launching and configuring scans security scans",
  },

  {
    field: "manage_billing",
    label: "Manage Billing",
    description: "Provides access to billing settings and invoices",
  },
];
