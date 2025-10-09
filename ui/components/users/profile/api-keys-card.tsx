import { getApiKeys } from "@/actions/api-keys/api-keys";

import { ApiKeysCardClient } from "./api-keys-card-client";

export const ApiKeysCard = async () => {
  const response = await getApiKeys();
  const apiKeys = response?.data
    ? response.data.filter((key) => !key.attributes.revoked)
    : [];
  const included = response?.included || [];

  return <ApiKeysCardClient initialApiKeys={apiKeys} included={included} />;
};
