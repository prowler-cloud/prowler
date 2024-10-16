"use server";

import { revalidatePath } from "next/cache";
import { redirect } from "next/navigation";

import { auth } from "@/auth.config";
import { parseStringify } from "@/lib";

export const getFindings = async ({
  page = 1,
  query = "",
  sort = "",
  filters = {},
}) => {
  const session = await auth();

  if (isNaN(Number(page)) || page < 1) redirect("/findings");

  const keyServer = process.env.API_BASE_URL;
  const url = new URL(
    `${keyServer}/findings?filter[inserted_at__gte]=2024-01-01`,
  );

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
    const providers = await fetch(url.toString(), {
      headers: {
        Accept: "application/vnd.api+json",
        Authorization: `Bearer ${session?.accessToken}`,
      },
    });
    const data = await providers.json();
    const parsedData = parseStringify(data);
    revalidatePath("/findings");
    return parsedData;
  } catch (error) {
    console.error("Error fetching findings:", error);
    return undefined;
  }
};
