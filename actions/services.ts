"use server";

import { revalidatePath } from "next/cache";
import { redirect } from "next/navigation";

import { parseStringify } from "@/lib";

export const getService = async ({ page = 1 }) => {
  if (isNaN(Number(page)) || page < 1) redirect("/services");
  const keyServer = process.env.SITE_URL;

  try {
    const services = await fetch(
      `${keyServer}/api/services?page%5Bnumber%5D=${page}`,
    );
    const data = await services.json();
    const parsedData = parseStringify(data);
    revalidatePath("/services");
    return parsedData;
  } catch (error) {
    console.error("Error fetching services:", error);
    return undefined;
  }
};

export const getErrorMessage = (error: unknown): string => {
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
