import { describe, expect, it } from "vitest";

import { getComplianceIcon } from "./IconCompliance";

describe("getComplianceIcon", () => {
  describe("framework name matching", () => {
    it("resolves ASD Essential Eight via the `essential` keyword", () => {
      expect(getComplianceIcon("ASD-Essential-Eight")).toBeDefined();
      expect(getComplianceIcon("asd-essential-eight")).toBeDefined();
      expect(getComplianceIcon("ASD Essential Eight Maturity Model")).toBe(
        getComplianceIcon("ASD-Essential-Eight"),
      );
    });

    it("returns undefined for an unknown framework name", () => {
      expect(getComplianceIcon("Made-Up-Framework")).toBeUndefined();
    });

    it("returns undefined for an empty string", () => {
      expect(getComplianceIcon("")).toBeUndefined();
    });
  });

  describe("compliance_id matching (with provider suffix)", () => {
    // Regression coverage for the icon-shadowing bug: every AWS-hosted
    // compliance_id ends with `_aws`, so `getComplianceIcon` MUST resolve
    // by the framework keyword (cis, iso, ...) before falling through to
    // the provider-level `aws` keyword. If `aws` ever moves up in
    // COMPLIANCE_LOGOS, every assertion below will flip and surface the
    // regression.

    it("resolves CIS variants by the framework keyword, not by `aws`", () => {
      const cisLogo = getComplianceIcon("CIS");
      expect(cisLogo).toBeDefined();
      expect(getComplianceIcon("cis_4.0_aws")).toBe(cisLogo);
      expect(getComplianceIcon("cis_5.0_aws")).toBe(cisLogo);
      expect(getComplianceIcon("cis_6.0_aws")).toBe(cisLogo);
    });

    it("resolves CISA before falling back to CIS or AWS", () => {
      const cisLogo = getComplianceIcon("CIS");
      const cisaLogo = getComplianceIcon("cisa");
      expect(cisaLogo).toBeDefined();
      expect(cisaLogo).not.toBe(cisLogo);
      expect(getComplianceIcon("cisa_aws")).toBe(cisaLogo);
    });

    it("resolves ISO 27001 by the framework keyword, not by `aws`", () => {
      const isoLogo = getComplianceIcon("ISO27001");
      expect(isoLogo).toBeDefined();
      expect(getComplianceIcon("iso27001_2022_aws")).toBe(isoLogo);
      expect(getComplianceIcon("iso27001_2013_aws")).toBe(isoLogo);
    });

    it("resolves Prowler ThreatScore by the framework keyword, not by `aws`", () => {
      const threatLogo = getComplianceIcon("ProwlerThreatScore");
      expect(threatLogo).toBeDefined();
      expect(getComplianceIcon("prowler_threatscore_aws")).toBe(threatLogo);
    });

    it("resolves the Okta IDaaS STIG via the `okta` keyword", () => {
      const oktaLogo = getComplianceIcon("Okta-IDaaS-STIG");
      expect(oktaLogo).toBeDefined();
      expect(getComplianceIcon("okta_idaas_stig_v1r2_okta")).toBe(oktaLogo);
    });

    it("resolves ASD Essential Eight by the framework keyword, not by `aws`", () => {
      const essentialLogo = getComplianceIcon("ASD-Essential-Eight");
      expect(essentialLogo).toBeDefined();
      expect(getComplianceIcon("asd_essential_eight_aws")).toBe(essentialLogo);
    });

    it("resolves NIS2 distinctly from NIST", () => {
      const nis2Logo = getComplianceIcon("NIS2");
      const nistLogo = getComplianceIcon("NIST-800-53");
      expect(nis2Logo).toBeDefined();
      expect(nistLogo).toBeDefined();
      expect(nis2Logo).not.toBe(nistLogo);
      expect(getComplianceIcon("nis2_aws")).toBe(nis2Logo);
      expect(getComplianceIcon("nist_800_53_revision_5_aws")).toBe(nistLogo);
    });

    it("resolves PCI/HIPAA/GDPR/SOC2/ENS/FedRAMP/MITRE/RBI/KISA/SecNumCloud by their framework keyword", () => {
      // Spot-check the rest of the framework keywords against AWS-suffixed ids.
      // Each must resolve to a distinct logo from `aws` so the watchlist
      // surface (which keys icons by compliance_id) renders correctly.
      const awsLogo = getComplianceIcon(
        "AWS-Well-Architected-Framework-Security-Pillar",
      );
      const cases = [
        "pci_4.0_aws",
        "hipaa_aws",
        "gdpr_aws",
        "soc2_aws",
        "ens_rd2022_aws",
        "fedramp_low_revision_4_aws",
        "mitre_attack_aws",
        "rbi_cyber_security_framework_aws",
        "kisa_isms_p_2023_aws",
        "secnumcloud_3.2_aws",
      ];
      for (const id of cases) {
        const resolved = getComplianceIcon(id);
        expect(
          resolved,
          `${id} should resolve to a framework-specific logo, not the AWS fallback`,
        ).toBeDefined();
        expect(
          resolved,
          `${id} should not collapse to the generic AWS logo`,
        ).not.toBe(awsLogo);
      }
    });
  });

  describe("AWS-only frameworks fall through to the AWS logo", () => {
    // These frameworks are genuinely AWS-specific and have no other matching
    // keyword in the registry. They must resolve to the AWS logo via the
    // tail-end fallback.

    it("resolves AWS Well-Architected pillars to the AWS logo", () => {
      const awsLogo = getComplianceIcon(
        "AWS-Well-Architected-Framework-Security-Pillar",
      );
      expect(awsLogo).toBeDefined();
      expect(
        getComplianceIcon("AWS-Well-Architected-Framework-Reliability-Pillar"),
      ).toBe(awsLogo);
      expect(
        getComplianceIcon("aws_well_architected_framework_security_pillar_aws"),
      ).toBe(awsLogo);
    });

    it("resolves AWS Foundational frameworks to the AWS logo", () => {
      const awsLogo = getComplianceIcon(
        "AWS-Well-Architected-Framework-Security-Pillar",
      );
      expect(
        getComplianceIcon("aws_foundational_security_best_practices_aws"),
      ).toBe(awsLogo);
      expect(getComplianceIcon("aws_foundational_technical_review_aws")).toBe(
        awsLogo,
      );
      expect(
        getComplianceIcon("aws_audit_manager_control_tower_guardrails_aws"),
      ).toBe(awsLogo);
      expect(getComplianceIcon("aws_account_security_onboarding_aws")).toBe(
        awsLogo,
      );
    });
  });
});
