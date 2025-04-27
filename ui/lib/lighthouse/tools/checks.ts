import { tool } from "@langchain/core/tools";

import { getLighthouseProviderChecks } from "@/lib/lighthouse/helpers/checks";
import { checkSchema } from "@/types/lighthouse";

export const getProviderChecksTool = tool(
  async ({ provider_type }) => {
    const checks = await getLighthouseProviderChecks(provider_type);
    return checks;
  },
  {
    name: "getProviderChecks",
    description:
      "Returns a list of available checks for a specific provider (aws, gcp, azure, kubernetes)",
    schema: checkSchema,
  },
);
