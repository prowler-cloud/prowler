import "server-only";

import { parseStringify } from "../utils";

export const getProvider = async () => {
  try {
    const providers = await fetch("http://localhost:3000/api/providers");
    const data = await providers.json();
    return parseStringify(data);
  } catch (error) {
    console.log(error);
  }
};
