import "server-only";

import { parseStringify } from "../utils";

export const getProvider = async () => {
  const key = process.env.LOCAL_SITE_URL;
  try {
    const providers = await fetch(`${key}/api/providers`);
    const data = await providers.json();
    return parseStringify(data);
  } catch (error) {
    console.log(error);
  }
};
