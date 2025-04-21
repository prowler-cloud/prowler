import { tool } from "@langchain/core/tools";

import { aiGetProviderChecks } from "@/lib/lighthouse/helperChecks";
import { checkSchema } from "@/types/ai/checks";

export const getProviderChecksTool = tool(
  async ({ provider_type }) => {
    const checks = await aiGetProviderChecks(provider_type);
    return checks;
  },
  {
    name: "getProviderChecks",
    description:
      "Returns a list of available checks for a specific provider (aws, gcp, azure, kubernetes)",
    schema: checkSchema,
  },
);
