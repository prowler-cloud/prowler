import { getApiKeys } from "@/actions/api-keys/api-keys";
import { SearchParamsProps } from "@/types";

import { ApiKeysCardClient } from "./api-keys-card-client";

export const ApiKeysCard = async ({
  searchParams,
}: {
  searchParams: SearchParamsProps;
}) => {
  const page = parseInt(searchParams.page?.toString() || "1", 10);
  const pageSize = parseInt(searchParams.pageSize?.toString() || "10", 10);
  const sort = searchParams.sort?.toString();

  const apiKeysResponse = await getApiKeys({ page, pageSize, sort });

  return (
    <ApiKeysCardClient
      initialApiKeys={apiKeysResponse.data}
      metadata={apiKeysResponse.metadata}
    />
  );
};
