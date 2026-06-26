import { redirect } from "next/navigation";

export default async function LighthouseConfigConnectRedirectPage({
  searchParams,
}: {
  searchParams: Promise<Record<string, string | string[] | undefined>>;
}) {
  await redirectWithSearchParams(searchParams, "/lighthouse/settings/connect");
}

async function redirectWithSearchParams(
  searchParams: Promise<Record<string, string | string[] | undefined>>,
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
