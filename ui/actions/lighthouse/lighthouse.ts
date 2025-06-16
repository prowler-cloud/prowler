"use server";

import { apiBaseUrl, getAuthHeaders } from "@/lib/helper";

export const getAIKey = async (): Promise<string> => {
  const headers = await getAuthHeaders({ contentType: false });
  const url = new URL(
    `${apiBaseUrl}/lighthouse-configurations?fields[lighthouse-config]=api_key`,
  );

  try {
    const response = await fetch(url.toString(), {
      method: "GET",
      headers,
    });

    const data = await response.json();

    // Check if data array exists and has at least one item
    if (data?.data && data.data.length > 0) {
      return data.data[0].attributes.api_key || "";
    }

    // Return empty string if no configuration found
    return "";
  } catch (error) {
    console.error("[Server] Error in getAIKey:", error);
    return "";
  }
};

export const checkLighthouseConnection = async (configId: string) => {
  const headers = await getAuthHeaders({ contentType: false });
  const url = new URL(
    `${apiBaseUrl}/lighthouse-configurations/${configId}/connection`,
  );

  try {
    const response = await fetch(url.toString(), {
      method: "POST",
      headers,
    });

    const data = await response.json();
    return data;
  } catch (error) {
    console.error("[Server] Error in checkLighthouseConnection:", error);
    return undefined;
  }
};

export const createLighthouseConfig = async (config: {
  model: string;
  apiKey: string;
  businessContext: string;
}) => {
  const headers = await getAuthHeaders({ contentType: true });
  const url = new URL(`${apiBaseUrl}/lighthouse-configurations`);
  try {
    const payload = {
      data: {
        type: "lighthouse-configurations",
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

    // Trigger connection check in background
    if (data?.data?.id) {
      checkLighthouseConnection(data.data.id);
    }

    return data;
  } catch (error) {
    console.error("[Server] Error in createLighthouseConfig:", error);
    return undefined;
  }
};

export const getLighthouseConfig = async () => {
  const headers = await getAuthHeaders({ contentType: false });
  const url = new URL(`${apiBaseUrl}/lighthouse-configurations`);

  try {
    const response = await fetch(url.toString(), {
      method: "GET",
      headers,
    });
    const data = await response.json();

    // Check if data array exists and has at least one item
    if (data?.data && data.data.length > 0) {
      return data.data[0];
    }

    return undefined;
  } catch (error) {
    console.error("[Server] Error in getLighthouseConfig:", error);
    return undefined;
  }
};

export const updateLighthouseConfig = async (config: {
  model: string;
  apiKey: string;
  businessContext: string;
}) => {
  const headers = await getAuthHeaders({ contentType: true });

  // Get the config ID from the list endpoint
  const url = new URL(`${apiBaseUrl}/lighthouse-configurations`);
  try {
    const response = await fetch(url.toString(), {
      method: "GET",
      headers: await getAuthHeaders({ contentType: false }),
    });

    const data = await response.json();

    // Check if data array exists and has at least one item
    if (!data?.data || data.data.length === 0) {
      return undefined;
    }

    const configId = data.data[0].id;
    const updateUrl = new URL(
      `${apiBaseUrl}/lighthouse-configurations/${configId}`,
    );

    // Prepare the request payload following the JSONAPI format
    const payload = {
      data: {
        type: "lighthouse-configurations",
        id: configId,
        attributes: {
          model: config.model,
          api_key: config.apiKey,
          business_context: config.businessContext,
        },
      },
    };

    const updateResponse = await fetch(updateUrl.toString(), {
      method: "PATCH",
      headers,
      body: JSON.stringify(payload),
    });

    const updateData = await updateResponse.json();

    // Trigger connection check in background
    if (updateData?.data?.id || configId) {
      checkLighthouseConnection(configId);
    }

    return updateData;
  } catch (error) {
    console.error("[Server] Error in updateLighthouseConfig:", error);
    return undefined;
  }
};
