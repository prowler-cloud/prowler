import { type ClassValue, clsx } from "clsx";
import { twMerge } from "tailwind-merge";

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}

export const SPECIAL_CHARACTERS = "!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~";

/**
 * Calculates a percentage and rounds it to the nearest integer
 * @param value - The numerator value
 * @param total - The denominator value
 * @returns The rounded percentage (0-100), or 0 if total is 0
 */
export function calculatePercentage(value: number, total: number): number {
  if (total === 0) return 0;
  return Math.round((value / total) * 100);
}

/**
 * Normalizes a value into an optional display string.
 * @param value - The value to normalize
 * @returns The original string when it is non-empty and not the "-" placeholder, otherwise undefined
 */
export function getOptionalText(value: unknown): string | undefined {
  return typeof value === "string" && value.trim().length > 0 && value !== "-"
    ? value
    : undefined;
}
