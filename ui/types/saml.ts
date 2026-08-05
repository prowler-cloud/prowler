export const SAML_CONFIGURATION_RESOURCE_TYPE = "saml-configurations" as const;
export const MAX_SAML_ADDITIONAL_EMAIL_DOMAINS = 19;

export interface SamlConfigurationAttributes {
  email_domain: string;
  additional_email_domains?: string[];
  metadata_xml?: string;
  created_at?: string;
  updated_at?: string;
}

export interface SamlConfiguration {
  id: string;
  type?: typeof SAML_CONFIGURATION_RESOURCE_TYPE;
  attributes?: SamlConfigurationAttributes;
}

export interface SamlConfigurationErrors {
  email_domain?: string;
  additional_email_domains?: string;
  metadata_xml?: string;
  general?: string;
}

export type SamlConfigurationActionState = {
  errors?: SamlConfigurationErrors;
  success?: string;
} | null;

interface SamlConfigurationRequestAttributes {
  email_domain: string;
  additional_email_domains?: string[];
}

export interface SamlConfigurationCreateRequestAttributes
  extends SamlConfigurationRequestAttributes {
  metadata_xml: string;
}

export interface SamlConfigurationUpdateRequestAttributes
  extends SamlConfigurationRequestAttributes {
  metadata_xml?: string;
}
