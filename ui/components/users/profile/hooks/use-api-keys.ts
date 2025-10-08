import { useCallback, useEffect, useState } from "react";

import { getApiKeys } from "@/actions/api-keys/api-keys";
import { ApiKeyData } from "@/types/api-keys";

export const useApiKeys = () => {
  const [apiKeys, setApiKeys] = useState<ApiKeyData[]>([]);
  const [isLoading, setIsLoading] = useState(true);

  const loadApiKeys = useCallback(async () => {
    setIsLoading(true);
    const response = await getApiKeys();
    if (response?.data) {
      // Filter out revoked keys (they are effectively deleted)
      const activeKeys = response.data.filter((key) => !key.attributes.revoked);
      setApiKeys(activeKeys);
    }
    setIsLoading(false);
  }, []);

  useEffect(() => {
    loadApiKeys();
  }, [loadApiKeys]);

  return {
    apiKeys,
    isLoading,
    refetch: loadApiKeys,
  };
};
