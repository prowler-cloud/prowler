import { getTask } from "@/actions/task";
import { MetaDataProps } from "@/types";

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

export const regions = [
  // AWS Regions (ordered by usage)
  { key: "us-east-1", label: "AWS - US East 1" },
  { key: "us-west-1", label: "AWS - US West 1" },
  { key: "us-west-2", label: "AWS - US West 2" },
  { key: "eu-west-1", label: "AWS - EU West 1" },
  { key: "eu-central-1", label: "AWS - EU Central 1" },
  { key: "ap-southeast-1", label: "AWS - AP Southeast 1" },
  { key: "ap-northeast-1", label: "AWS - AP Northeast 1" },
  { key: "ap-southeast-2", label: "AWS - AP Southeast 2" },
  { key: "ca-central-1", label: "AWS - CA Central 1" },
  { key: "sa-east-1", label: "AWS - SA East 1" },
  { key: "af-south-1", label: "AWS - AF South 1" },
  { key: "ap-east-1", label: "AWS - AP East 1" },
  { key: "ap-northeast-2", label: "AWS - AP Northeast 2" },
  { key: "ap-northeast-3", label: "AWS - AP Northeast 3" },
  { key: "ap-south-1", label: "AWS - AP South 1" },
  { key: "ap-south-2", label: "AWS - AP South 2" },
  { key: "ap-southeast-3", label: "AWS - AP Southeast 3" },
  { key: "ap-southeast-4", label: "AWS - AP Southeast 4" },
  { key: "ca-west-1", label: "AWS - CA West 1" },
  { key: "eu-central-2", label: "AWS - EU Central 2" },
  { key: "eu-north-1", label: "AWS - EU North 1" },
  { key: "eu-south-1", label: "AWS - EU South 1" },
  { key: "eu-south-2", label: "AWS - EU South 2" },
  { key: "eu-west-2", label: "AWS - EU West 2" },
  { key: "eu-west-3", label: "AWS - EU West 3" },
  { key: "il-central-1", label: "AWS - IL Central 1" },
  { key: "me-central-1", label: "AWS - ME Central 1" },
  { key: "me-south-1", label: "AWS - ME South 1" },

  // Azure Regions (ordered by usage)
  { key: "eastus", label: "Azure - East US" },
  { key: "eastus2", label: "Azure - East US 2" },
  { key: "westeurope", label: "Azure - West Europe" },
  { key: "southeastasia", label: "Azure - Southeast Asia" },
  { key: "uksouth", label: "Azure - UK South" },
  { key: "northeurope", label: "Azure - North Europe" },
  { key: "centralus", label: "Azure - Central US" },
  { key: "westus2", label: "Azure - West US 2" },
  { key: "southcentralus", label: "Azure - South Central US" },
  { key: "australiaeast", label: "Azure - Australia East" },
  { key: "canadacentral", label: "Azure - Canada Central" },
  { key: "japaneast", label: "Azure - Japan East" },
  { key: "koreacentral", label: "Azure - Korea Central" },
  { key: "southafricanorth", label: "Azure - South Africa North" },
  { key: "brazilsouth", label: "Azure - Brazil South" },
  { key: "francecentral", label: "Azure - France Central" },
  { key: "germanywestcentral", label: "Azure - Germany West Central" },
  { key: "switzerlandnorth", label: "Azure - Switzerland North" },
  { key: "uaenorth", label: "Azure - UAE North" },
  // Remaining Azure Regions (less frequently used)
  { key: "westus", label: "Azure - West US" },
  { key: "northcentralus", label: "Azure - North Central US" },
  { key: "australiasoutheast", label: "Azure - Australia Southeast" },
  { key: "southindia", label: "Azure - South India" },
  { key: "westindia", label: "Azure - West India" },
  { key: "canadaeast", label: "Azure - Canada East" },
  { key: "francesouth", label: "Azure - France South" },
  { key: "norwayeast", label: "Azure - Norway East" },
  { key: "switzerlandwest", label: "Azure - Switzerland West" },
  { key: "ukwest", label: "Azure - UK West" },
  { key: "uaecentral", label: "Azure - UAE Central" },
  { key: "brazilsoutheast", label: "Azure - Brazil Southeast" },

  // GCP Regions (ordered by usage)
  { key: "us-central1", label: "GCP - US Central (Iowa)" },
  { key: "us-east1", label: "GCP - US East (South Carolina)" },
  { key: "us-west1", label: "GCP - US West (Oregon)" },
  { key: "europe-west1", label: "GCP - Europe West (Belgium)" },
  { key: "asia-east1", label: "GCP - Asia East (Taiwan)" },
  { key: "asia-northeast1", label: "GCP - Asia Northeast (Tokyo)" },
  { key: "europe-west2", label: "GCP - Europe West (London)" },
  { key: "europe-west3", label: "GCP - Europe West (Frankfurt)" },
  { key: "europe-west4", label: "GCP - Europe West (Netherlands)" },
  { key: "asia-southeast1", label: "GCP - Asia Southeast (Singapore)" },
  { key: "australia-southeast1", label: "GCP - Australia Southeast (Sydney)" },
  {
    key: "northamerica-northeast1",
    label: "GCP - North America Northeast (Montreal)",
  },
  // Remaining GCP Regions
  { key: "asia-east2", label: "GCP - Asia East (Hong Kong)" },
  { key: "asia-northeast2", label: "GCP - Asia Northeast (Osaka)" },
  { key: "asia-northeast3", label: "GCP - Asia Northeast (Seoul)" },
  { key: "asia-south1", label: "GCP - Asia South (Mumbai)" },
  { key: "asia-southeast2", label: "GCP - Asia Southeast (Jakarta)" },
  { key: "europe-north1", label: "GCP - Europe North (Finland)" },
  { key: "europe-west6", label: "GCP - Europe West (Zurich)" },
  { key: "southamerica-east1", label: "GCP - South America East (São Paulo)" },
  { key: "us-west2", label: "GCP - US West (Los Angeles)" },
  { key: "us-east4", label: "GCP - US East (Northern Virginia)" },
];
