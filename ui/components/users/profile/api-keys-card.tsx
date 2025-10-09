import { getApiKeys } from "@/actions/api-keys/api-keys";

import { ApiKeysCardClient } from "./api-keys-card-client";

export const ApiKeysCard = async () => {
  const apiKeys = await getApiKeys();

  return <ApiKeysCardClient initialApiKeys={apiKeys} />;
};
