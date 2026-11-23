import { buildProviderWizardContext } from "@/lib/lighthouse/context/contributions";
import {
  LIGHTHOUSE_CONTEXT_TRANSPORT,
  type LighthouseContextEnvelope,
} from "@/types/lighthouse-context";

export function buildProviderWizardHelpContext(
  input: Parameters<typeof buildProviderWizardContext>[0],
): LighthouseContextEnvelope {
  return {
    schemaVersion: 1,
    transport: LIGHTHOUSE_CONTEXT_TRANSPORT.INLINE,
    items: [buildProviderWizardContext(input)],
  };
}
