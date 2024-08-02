import "server-only";

import { parseStringify } from "@/lib";

export const getProvider = async () => {
  const keyServer = process.env.LOCAL_SERVER_URL;

  try {
    const providers = await fetch(`${keyServer}/providers`, {
      headers: {
        "X-Tenant-ID": "12646005-9067-4d2a-a098-8bb378604362",
      },
    });

    const data = await providers.json();
    return parseStringify(data);
  } catch (error) {
    return undefined;
  }
};
