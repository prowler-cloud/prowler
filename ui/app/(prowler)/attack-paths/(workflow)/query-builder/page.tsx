import { redirect } from "next/navigation";

import { SearchParamsProps } from "@/types";

const buildQueryString = (searchParams: SearchParamsProps) => {
  const params = new URLSearchParams();

  for (const [key, value] of Object.entries(searchParams)) {
    if (Array.isArray(value)) {
      value.forEach((item) => params.append(key, item));
      continue;
    }

    if (typeof value === "string") {
      params.set(key, value);
    }
  }

  return params.toString();
};

export default async function AttackPathsQueryBuilderRedirectPage({
  searchParams,
}: {
  searchParams: Promise<SearchParamsProps>;
}) {
  const resolvedSearchParams = await searchParams;
  const queryString = buildQueryString(resolvedSearchParams);

  redirect(queryString ? `/attack-paths?${queryString}` : "/attack-paths");
}
