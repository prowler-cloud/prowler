"use server";
import { revalidatePath } from "next/cache";
import { redirect } from "next/navigation";

import { auth } from "@/auth.config";
import { parseStringify } from "@/lib";

export const getProvidersOverview = async ({
  page = 1,
  query = "",
  sort = "",
  filters = {},
}) => {
  const session = await auth();

  if (isNaN(Number(page)) || page < 1) redirect("/providers-overview");

  const keyServer = process.env.API_BASE_URL;
  const url = new URL(`${keyServer}/overviews/providers`);

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
    const response = await fetch(url.toString(), {
      headers: {
        Accept: "application/vnd.api+json",
        Authorization: `Bearer ${session?.accessToken}`,
      },
    });

    const data = await response.json();
    const parsedData = parseStringify(data);
    revalidatePath("/");
    return parsedData;
  } catch (error) {
    // eslint-disable-next-line no-console
    console.error("Error fetching providers overview:", error);
    return undefined;
  }
};

export const getFindingsByStatus = async ({
  page = 1,
  query = "",
  sort = "",
  filters = {},
}) => {
  const session = await auth();

  if (isNaN(Number(page)) || page < 1) redirect("/");

  const keyServer = process.env.API_BASE_URL;
  const url = new URL(`${keyServer}/overviews/findings`);

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
    const response = await fetch(url.toString(), {
      headers: {
        Accept: "application/vnd.api+json",
        Authorization: `Bearer ${session?.accessToken}`,
      },
    });

    if (!response.ok) {
      throw new Error(`Failed to fetch findings severity: ${response.status}`);
    }

    const data = await response.json();
    const parsedData = parseStringify(data);
    revalidatePath("/");
    return parsedData;
  } catch (error) {
    // eslint-disable-next-line no-console
    console.error("Error fetching findings severity overview:", error);
    return undefined;
  }
};

export const getFindingsBySeverity = async ({
  page = 1,
  query = "",
  sort = "",
  filters = {},
}) => {
  const session = await auth();

  if (isNaN(Number(page)) || page < 1) redirect("/");

  const keyServer = process.env.API_BASE_URL;
  const url = new URL(`${keyServer}/overviews/findings_severity`);

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
    const response = await fetch(url.toString(), {
      headers: {
        Accept: "application/vnd.api+json",
        Authorization: `Bearer ${session?.accessToken}`,
      },
    });

    if (!response.ok) {
      throw new Error(`Failed to fetch findings severity: ${response.status}`);
    }

    const data = await response.json();
    const parsedData = parseStringify(data);
    revalidatePath("/");
    return parsedData;
  } catch (error) {
    // eslint-disable-next-line no-console
    console.error("Error fetching findings severity overview:", error);
    return undefined;
  }
};
