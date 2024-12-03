"use server";

import { revalidatePath } from "next/cache";
import { redirect } from "next/navigation";

import { auth } from "@/auth.config";
import { parseStringify } from "@/lib";

export const getFindings = async ({
  page = 1,
  pageSize = 10,
  query = "",
  sort = "",
  filters = {},
}) => {
  const session = await auth();

  if (isNaN(Number(page)) || page < 1)
    redirect("findings?include=resources.provider,scan");

  const keyServer = process.env.API_BASE_URL;
  const url = new URL(`${keyServer}/findings?include=resources.provider,scan`);

  if (page) url.searchParams.append("page[number]", page.toString());
  if (pageSize) url.searchParams.append("page[size]", pageSize.toString());

  if (query) url.searchParams.append("filter[search]", query);
  if (sort) url.searchParams.append("sort", sort);

  Object.entries(filters).forEach(([key, value]) => {
    if (key !== "filter[search]") {
      url.searchParams.append(key, String(value));
    }
  });

  try {
    const findings = await fetch(url.toString(), {
      headers: {
        Accept: "application/vnd.api+json",
        Authorization: `Bearer ${session?.accessToken}`,
      },
    });
    const data = await findings.json();
    const parsedData = parseStringify(data);
    revalidatePath("/findings");
    return parsedData;
  } catch (error) {
    // eslint-disable-next-line no-console
    console.error("Error fetching findings:", error);
    return undefined;
  }
};

export const getServicesRegions = async ({
  query = "",
  sort = "",
  filters = {},
}) => {
  const session = await auth();

  const keyServer = process.env.API_BASE_URL;
  const url = new URL(`${keyServer}/findings/findings_services_regions`);

  if (query) url.searchParams.append("filter[search]", query);
  if (sort) url.searchParams.append("sort", sort);

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
      throw new Error(
        `Failed to fetch services regions: ${response.statusText}`,
      );
    }

    const data = await response.json();
    const parsedData = parseStringify(data);
    return parsedData;
  } catch (error) {
    // eslint-disable-next-line no-console
    console.error("Error fetching services regions:", error);
    return undefined;
  }
};
