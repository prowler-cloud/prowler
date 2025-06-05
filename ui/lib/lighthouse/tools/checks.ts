import { tool } from "@langchain/core/tools";

import {
  getLighthouseCheckDetails,
  getLighthouseProviderChecks,
} from "@/actions/lighthouse/checks";
import { checkDetailsSchema, checkSchema } from "@/types/lighthouse";

export const getProviderChecksTool = tool(
  async ({ providerType, service, severity, compliances }) => {
    const checks = await getLighthouseProviderChecks({
      providerType,
      service: service || [],
      severity: severity || [],
      compliances: compliances || [],
    });
    return checks;
  },
  {
    name: "getProviderChecks",
    description:
      "Returns a list of available checks for a specific provider (aws, gcp, azure, kubernetes). Allows filtering by service, severity, and compliance framework ID. If no filters are provided, all checks will be returned.",
    schema: checkSchema,
  },
);

export const getProviderCheckDetailsTool = tool(
  async ({ checkId }: { checkId: string }) => {
    const check = await getLighthouseCheckDetails({ checkId });
    return check;
  },
  {
    name: "getCheckDetails",
    description:
      "Returns the details of a specific check including details about severity, risk, remediation, compliances that are associated with the check, etc",
    schema: checkDetailsSchema,
  },
);
