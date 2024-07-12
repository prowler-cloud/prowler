import type { ClassValue } from "clsx";
import clsx from "clsx";
import { twMerge } from "tailwind-merge";

// Definition of custom classes you want to combine
const customClasses = new Map<string, string>([
  ["text-small", "text-small"],
  ["text-default-500", "text-default-500"],
  // Add more custom classes as needed
]);

export function cn(...inputs: ClassValue[]) {
  // Filter and combine custom classes before passing them to twMerge
  const filteredInputs = inputs.map((input) => {
    if (typeof input === "string") {
      return customClasses.get(input) || input;
    }
    return input;
  });

  return twMerge(clsx(filteredInputs));
}
