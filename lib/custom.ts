import { MetaDataProps } from "@/types";

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
