import { getTask } from "@/actions/task";
import { AuthSocialProvider, MetaDataProps, PermissionInfo } from "@/types";

export const baseUrl = process.env.AUTH_URL || "http://localhost:3000";

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

export const isGoogleOAuthEnabled =
  process.env.SOCIAL_GOOGLE_OAUTH_CLIENT_ID !== "" &&
  process.env.SOCIAL_GOOGLE_OAUTH_CLIENT_SECRET !== "";

export const isGithubOAuthEnabled =
  process.env.SOCIAL_GITHUB_OAUTH_CLIENT_ID !== "" &&
  process.env.SOCIAL_GITHUB_OAUTH_CLIENT_SECRET !== "";

export async function checkTaskStatus(
  taskId: string,
): Promise<{ completed: boolean; error?: string }> {
  const MAX_RETRIES = 20; // Define the maximum number of attempts before stopping the polling
  const RETRY_DELAY = 1000; // Delay time between each poll (in milliseconds)

  for (let attempt = 0; attempt < MAX_RETRIES; attempt++) {
    const task = await getTask(taskId);

    if (task.error) {
      // eslint-disable-next-line no-console
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
        await new Promise((resolve) => setTimeout(resolve, RETRY_DELAY));
        break;
      default:
        return { completed: false, error: "Unexpected task state" };
    }
  }

  return { completed: false, error: "Max retries exceeded" };
}

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

  return { currentPage, totalPages, totalEntries };
};

export function encryptKey(passkey: string) {
  return btoa(passkey);
}

export function decryptKey(passkey: string) {
  return atob(passkey);
}

export const getErrorMessage = async (error: unknown): Promise<string> => {
  let message: string;

  if (error instanceof Error) {
    message = error.message;
  } else if (error && typeof error === "object" && "message" in error) {
    message = String(error.message);
  } else if (typeof error === "string") {
    message = error;
  } else {
    message = "Oops! Something went wrong.";
  }
  return message;
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
  // {
  //   field: "manage_integrations",
  //   label: "Manage Integrations",
  //   description:
  //     "Controls the setup and management of third-party integrations",
  // },
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
