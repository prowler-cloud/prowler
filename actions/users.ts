"use server";

import { revalidatePath } from "next/cache";
import { redirect } from "next/navigation";

import { parseStringify } from "@/lib";

export const getUsers = async ({ page = 1 }) => {
  if (isNaN(Number(page)) || page < 1) redirect("/users");
  const keyServer = process.env.SITE_URL;

  try {
    const users = await fetch(
      `${keyServer}/api/users?page%5Bnumber%5D=${page}`,
    );
    const data = await users.json();
    const parsedData = parseStringify(data);
    revalidatePath("/users");
    return parsedData;
  } catch (error) {
    console.error("Error fetching Users:", error);
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
