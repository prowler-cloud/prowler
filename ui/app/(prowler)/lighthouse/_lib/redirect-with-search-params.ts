import { redirect } from "next/navigation";

type SearchParams = Promise<Record<string, string | string[] | undefined>>;

export async function redirectWithSearchParams(
  searchParams: SearchParams,
  pathname: string,
) {
  const params = await searchParams;
  const query = new URLSearchParams();

  Object.entries(params).forEach(([key, value]) => {
    if (Array.isArray(value)) {
      value.forEach((item) => query.append(key, item));
      return;
    }

    if (typeof value === "string") {
      query.set(key, value);
    }
  });

  const queryString = query.toString();
  redirect(queryString ? `${pathname}?${queryString}` : pathname);
}
