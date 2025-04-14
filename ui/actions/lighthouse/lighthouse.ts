"use server";

import { apiBaseUrl, getAuthHeaders } from "@/lib/helper";

const getAIConfigurationId = async (): Promise<string> => {
  const headers = await getAuthHeaders({ contentType: false });
  const url = new URL(`${apiBaseUrl}/lighthouse-config?filter[name]=OpenAI`);
  try {
    const response = await fetch(url.toString(), {
      method: "GET",
      headers,
    });

    const data = await response.json();

    // Check if data array exists and has at least one item
    if (data?.data && data.data.length > 0) {
      return data.data[0].id;
    }

    // Return empty string if no configuration found
    return "";
  } catch (error) {
    console.error("[Server] Error in getOpenAIConfigurationId:", error);
    return "";
  }
};

export const getAIKey = async (): Promise<string> => {
  const headers = await getAuthHeaders({ contentType: false });
  const configId = await getAIConfigurationId();

  if (!configId) {
    console.log("AI configuration ID not found");
    return "";
  }

  const url = new URL(`${apiBaseUrl}/lighthouse-config/${configId}/show_key`);
  const response = await fetch(url.toString(), {
    method: "GET",
    headers,
  });

  const data = await response.json();
  return data.data.api_key;
};

export const createAIConfiguration = async (config: {
  model: string;
  apiKey: string;
  businessContext: string;
}) => {
  const headers = await getAuthHeaders({ contentType: true });
  const url = new URL(`${apiBaseUrl}/lighthouse-config`);
  try {
    const payload = {
      data: {
        type: "lighthouse-config",
        attributes: {
          name: "OpenAI",
          model: config.model,
          api_key: config.apiKey,
          business_context: config.businessContext,
        },
      },
    };

    const response = await fetch(url.toString(), {
      method: "POST",
      headers,
      body: JSON.stringify(payload),
    });
    const data = await response.json();
    return data;
  } catch (error) {
    console.error("[Server] Error in createAIConfiguration:", error);
    return undefined;
  }
};

export const getAIConfiguration = async () => {
  const headers = await getAuthHeaders({ contentType: false });
  const configId = await getAIConfigurationId();

  if (!configId) {
    console.log("AI configuration ID not found");
    return undefined;
  }

  const url = new URL(`${apiBaseUrl}/lighthouse-config/${configId}`);
  try {
    const response = await fetch(url.toString(), {
      method: "GET",
      headers,
    });
    const data = await response.json();
    return data;
  } catch (error) {
    console.error("[Server] Error in getAIConfiguration:", error);
    return undefined;
  }
};

export const updateAIConfiguration = async (config: {
  model: string;
  apiKey: string;
  businessContext: string;
}) => {
  const headers = await getAuthHeaders({ contentType: true });
  const configId = await getAIConfigurationId();

  if (!configId) {
    console.log("AI configuration ID not found");
    return undefined;
  }

  try {
    const url = new URL(`${apiBaseUrl}/lighthouse-config/${configId}`);

    // Prepare the request payload following the JSONAPI format
    const payload = {
      data: {
        type: "lighthouse-config",
        id: configId,
        attributes: {
          model: config.model,
          api_key: config.apiKey,
          business_context: config.businessContext,
        },
      },
    };

    const response = await fetch(url.toString(), {
      method: "PATCH",
      headers,
      body: JSON.stringify(payload),
    });

    const data = await response.json();
    return data;
  } catch (error) {
    console.error("[Server] Error in updateAIConfiguration:", error);
    return undefined;
  }
};
