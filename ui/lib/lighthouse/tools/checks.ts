import { tool } from "@langchain/core/tools";

import { getLighthouseProviderChecks } from "@/lib/lighthouse/helpers/checks";
import { checkSchema } from "@/types/lighthouse";

export const getProviderChecksTool = tool(
  async ({ providerType }) => {
    const checks = await getLighthouseProviderChecks(providerType);
    return checks;
  },
  {
    name: "getProviderChecks",
    description:
      "Returns a list of available checks for a specific provider (aws, gcp, azure, kubernetes)",
    schema: checkSchema,
  },
);
