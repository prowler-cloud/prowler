"use server";

import { revalidatePath } from "next/cache";
import { redirect } from "next/navigation";

import { auth } from "@/auth.config";
import { getErrorMessage, parseStringify } from "@/lib";

export const getScans = async ({
  page = 1,
  query = "",
  sort = "",
  filters = {},
}) => {
  const session = await auth();

  if (isNaN(Number(page)) || page < 1) redirect("/scans");

  const keyServer = process.env.API_BASE_URL;
  const url = new URL(`${keyServer}/scans`);

  if (page) url.searchParams.append("page[number]", page.toString());
  if (query) url.searchParams.append("filter[search]", query);
  if (sort) url.searchParams.append("sort", sort);

  // Handle multiple filters
  Object.entries(filters).forEach(([key, value]) => {
    if (key !== "filter[search]") {
      url.searchParams.append(key, String(value));
    }
  });

  try {
    const scans = await fetch(url.toString(), {
      headers: {
        Accept: "application/vnd.api+json",
        Authorization: `Bearer ${session?.accessToken}`,
      },
    });
    const data = await scans.json();
    const parsedData = parseStringify(data);
    revalidatePath("/scans");
    return parsedData;
  } catch (error) {
    // eslint-disable-next-line no-console
    console.error("Error fetching scans:", error);
    return undefined;
  }
};

export const getScansByState = async () => {
  const session = await auth();

  const keyServer = process.env.API_BASE_URL;
  const url = new URL(`${keyServer}/scans`);

  // Request only the necessary fields to optimize the response
  url.searchParams.append("fields[scans]", "state");

  try {
    const response = await fetch(url.toString(), {
      headers: {
        Accept: "application/vnd.api+json",
        Authorization: `Bearer ${session?.accessToken}`,
      },
    });

    if (!response.ok) {
      try {
        const errorData = await response.json();
        throw new Error(errorData?.message || "Failed to fetch scans by state");
      } catch {
        throw new Error("Failed to fetch scans by state");
      }
    }

    const data = await response.json();

    return parseStringify(data);
  } catch (error) {
    // eslint-disable-next-line no-console
    console.error("Error fetching scans by state:", error);
    return undefined;
  }
};

export const getScan = async (scanId: string) => {
  const session = await auth();

  const keyServer = process.env.API_BASE_URL;
  const url = new URL(`${keyServer}/scans/${scanId}`);

  try {
    const scan = await fetch(url.toString(), {
      headers: {
        Accept: "application/vnd.api+json",
        Authorization: `Bearer ${session?.accessToken}`,
      },
    });
    const data = await scan.json();
    const parsedData = parseStringify(data);

    return parsedData;
  } catch (error) {
    return {
      error: getErrorMessage(error),
    };
  }
};

export const scanOnDemand = async (formData: FormData) => {
  const session = await auth();
  const keyServer = process.env.API_BASE_URL;

  const providerId = formData.get("providerId");
  const scanName = formData.get("scanName") || undefined;

  if (!providerId) {
    return { error: "Provider ID is required" };
  }

  const url = new URL(`${keyServer}/scans`);

  try {
    const requestBody = {
      data: {
        type: "scans",
        attributes: scanName ? { name: scanName } : {},
        relationships: {
          provider: {
            data: {
              type: "providers",
              id: providerId,
            },
          },
        },
      },
    };

    const response = await fetch(url.toString(), {
      method: "POST",
      headers: {
        "Content-Type": "application/vnd.api+json",
        Accept: "application/vnd.api+json",
        Authorization: `Bearer ${session?.accessToken}`,
      },
      body: JSON.stringify(requestBody),
    });

    if (!response.ok) {
      try {
        const errorData = await response.json();
        throw new Error(errorData?.message || "Failed to start scan");
      } catch {
        throw new Error("Failed to start scan");
      }
    }

    const data = await response.json();

    revalidatePath("/scans");
    return parseStringify(data);
  } catch (error) {
    // eslint-disable-next-line no-console
    console.error("Error starting scan:", error);
    return { error: getErrorMessage(error) };
  }
};

export const scheduleDaily = async (formData: FormData) => {
  const session = await auth();
  const keyServer = process.env.API_BASE_URL;

  const providerId = formData.get("providerId");

  const url = new URL(`${keyServer}/schedules/daily`);

  try {
    const response = await fetch(url.toString(), {
      method: "POST",
      headers: {
        "Content-Type": "application/vnd.api+json",
        Accept: "application/vnd.api+json",
        Authorization: `Bearer ${session?.accessToken}`,
      },
      body: JSON.stringify({
        data: {
          type: "daily-schedules",
          attributes: {
            provider_id: providerId,
          },
        },
      }),
    });

    if (!response.ok) {
      throw new Error(`Failed to schedule daily: ${response.statusText}`);
    }

    const data = await response.json();
    revalidatePath("/scans");
    return parseStringify(data);
  } catch (error) {
    // eslint-disable-next-line no-console
    console.error(error);
    return {
      error: getErrorMessage(error),
    };
  }
};

export const updateScan = async (formData: FormData) => {
  const session = await auth();
  const keyServer = process.env.API_BASE_URL;

  const scanId = formData.get("scanId");
  const scanName = formData.get("scanName");

  const url = new URL(`${keyServer}/scans/${scanId}`);

  try {
    const response = await fetch(url.toString(), {
      method: "PATCH",
      headers: {
        "Content-Type": "application/vnd.api+json",
        Accept: "application/vnd.api+json",
        Authorization: `Bearer ${session?.accessToken}`,
      },
      body: JSON.stringify({
        data: {
          type: "scans",
          id: scanId,
          attributes: {
            name: scanName,
          },
        },
      }),
    });
    const data = await response.json();
    revalidatePath("/scans");
    return parseStringify(data);
  } catch (error) {
    // eslint-disable-next-line no-console
    console.error(error);
    return {
      error: getErrorMessage(error),
    };
  }
};

export const getExportsZip = async (scanId: string) => {
  const session = await auth();

  const keyServer = process.env.API_BASE_URL;
  const url = new URL(`${keyServer}/scans/${scanId}/report`);

  try {
    const response = await fetch(url.toString(), {
      headers: {
        Authorization: `Bearer ${session?.accessToken}`,
      },
    });

    if (!response.ok) {
      const errorData = await response.json();
      throw new Error(
        errorData?.errors?.[0]?.detail || "Failed to fetch report",
      );
    }

    // Get the blob data as an array buffer
    const arrayBuffer = await response.arrayBuffer();
    // Convert to base64
    const base64 = Buffer.from(arrayBuffer).toString("base64");

    return {
      success: true,
      data: base64,
      filename: `scan-${scanId}-report.zip`,
    };
  } catch (error) {
    return {
      error: getErrorMessage(error),
    };
  }
};
