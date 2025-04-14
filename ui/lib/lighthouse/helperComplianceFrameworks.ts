import { ProviderType } from "@/lib/helper";

export const complianceFrameworksByProvider = async (provider_type: string) => {
  const complianceFrameworks: Record<ProviderType, string[]> = {
    aws: [
      "aws_account_security_onboarding_aws",
      "aws_audit_manager_control_tower_guardrails_aws",
      "aws_foundational_security_best_practices_aws",
      "aws_foundational_technical_review_aws",
      "aws_well_architected_framework_reliability_pillar_aws",
      "aws_well_architected_framework_security_pillar_aws",
      "cis_1.4_aws",
      "cis_3.0_aws",
      "cis_1.5_aws",
      "cis_2.0_aws",
      "cisa_aws",
      "ens_rd2022_aws",
      "ffiec_aws",
      "fedramp_low_revision_4_aws",
      "fedramp_moderate_revision_4_aws",
      "gdpr_aws",
      "gxp_21_cfr_part_11_aws",
      "gxp_eu_annex_11_aws",
      "hipaa_aws",
      "iso27001_2013_aws",
      "kisa_isms_p_2023_aws",
      "kisa_isms_p_2023_korean_aws",
      "mitre_attack_aws",
      "nist_800_171_revision_2_aws",
      "nist_800_53_revision_4_aws",
      "nist_800_53_revision_5_aws",
      "nist_csf_1.1_aws",
      "pci_3.2.1_aws",
      "rbi_cyber_security_framework_aws",
      "soc2_aws",
    ],
    azure: [
      "cis_2.0_azure",
      "cis_2.1_azure",
      "cis_3.0_azure",
      "ens_rd2022_azure",
      "mitre_attack_azure",
    ],
    gcp: ["cis_2.0_gcp", "cis_3.0_gcp", "ens_rd2022_gcp", "mitre_attack_gcp"],
    kubernetes: ["cis_1.10_kubernetes", "cis_1.8_kubernetes"],
    microsoft365: [],
  };
  return complianceFrameworks[provider_type as ProviderType] || [];
};

export const aiGetComplianceFrameworks = async (provider_type: string) => {
  return await complianceFrameworksByProvider(provider_type);
};
