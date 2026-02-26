import { ProviderWizardMode } from "@/types/provider-wizard";
import { ProviderType } from "@/types/providers";

export interface ProviderWizardInitialData {
  providerId: string;
  providerType: ProviderType;
  providerUid: string;
  providerAlias: string | null;
  secretId?: string | null;
  via?: string | null;
  mode?: ProviderWizardMode;
}
