import { buildProviderWizardContext } from "@/lib/lighthouse/context/contributions";
import {
  LIGHTHOUSE_CONTEXT_TRANSPORT,
  type LighthouseContextEnvelope,
} from "@/types/lighthouse-context";

import { AWS_ACCESS_METHOD } from "./steps/aws/types";

const ORGANIZATIONS_CONNECTION_METHOD = "organizations";

interface ConnectionMethodInput {
  isOrganizationsFlow: boolean;
  providerType: string | null;
  // The method a stored account was connected with.
  via: string | null;
  // The AWS access method picked in the connect step, before it is submitted.
  awsDraftMethod?: string;
}

export function resolveConnectionMethod({
  isOrganizationsFlow,
  providerType,
  via,
  awsDraftMethod,
}: ConnectionMethodInput): string | null {
  if (isOrganizationsFlow) return ORGANIZATIONS_CONNECTION_METHOD;
  if (via) return via;
  // The AWS connect step starts on the role method until the user switches.
  if (providerType === "aws") return awsDraftMethod ?? AWS_ACCESS_METHOD.ROLE;
  return null;
}

export function buildProviderWizardHelpContext(
  input: Parameters<typeof buildProviderWizardContext>[0],
): LighthouseContextEnvelope {
  return {
    schemaVersion: 1,
    transport: LIGHTHOUSE_CONTEXT_TRANSPORT.INLINE,
    items: [buildProviderWizardContext(input)],
  };
}
