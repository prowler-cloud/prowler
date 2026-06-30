import { redirectWithSearchParams } from "@/app/(prowler)/lighthouse/_lib/redirect-with-search-params";

export default async function LighthouseConfigConnectRedirectPage({
  searchParams,
}: {
  searchParams: Promise<Record<string, string | string[] | undefined>>;
}) {
  await redirectWithSearchParams(searchParams, "/lighthouse/settings/connect");
}
