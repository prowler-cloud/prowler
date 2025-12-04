import { SearchParamsProps } from "@/types";

/**
 * Common props interface for SSR components that receive search params
 * from the page component for filter handling.
 */
export interface SSRComponentProps {
  searchParams: SearchParamsProps | undefined | null;
}
