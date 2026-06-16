import ANSSILogo from "./anssi.png";
import ASDEssentialEightLogo from "./asd-essential-eight.svg";
import AWSLogo from "./aws.svg";
import C5Logo from "./c5.svg";
import CCCLogo from "./ccc.svg";
import CISLogo from "./cis.svg";
import CISALogo from "./cisa.svg";
import CSALogo from "./csa.svg";
import DORALogo from "./dora.svg";
import ENSLogo from "./ens.png";
import FedRAMPLogo from "./fedramp.svg";
import FFIECLogo from "./ffiec.svg";
import GDPRLogo from "./gdpr.svg";
import GxPLogo from "./gxp-aws.svg";
import HIPAALogo from "./hipaa.svg";
import ISOLogo from "./iso-27001.svg";
import KISALogo from "./kisa.svg";
import MITRELogo from "./mitre-attack.svg";
import NIS2Logo from "./nis2.svg";
import NISTLogo from "./nist.svg";
import OktaLogo from "./okta.svg";
import PCILogo from "./pci-dss.svg";
import PROWLERTHREATLogo from "./prowlerThreat.svg";
import RBILogo from "./rbi.svg";
import SOC2Logo from "./soc2.svg";

// Framework-specific keywords MUST come before the generic provider-level
// `aws` keyword. `getComplianceIcon` resolves by substring `includes`, and
// AWS compliance ids carry a `_aws` provider suffix (e.g. `cis_4.0_aws`,
// `iso27001_2022_aws`, `prowler_threatscore_aws`, `asd_essential_eight_aws`).
// Without this ordering the generic `aws` entry would shadow every
// framework-specific logo on watchlist surfaces that resolve by id. The
// list is a tuple array (rather than an object literal) because lookup
// order is semantically meaningful here — JavaScript engines preserve
// insertion order for string keys, but a tuple makes that contract
// explicit and prevents an accidental object-literal sort or
// `Object.fromEntries` round-trip from silently breaking resolution.
// `aws` is intentionally last so the framework keywords win, while genuinely
// AWS-only frameworks (Well-Architected, Audit Manager, Foundational Security
// Best Practices, Account Security Onboarding, Foundational Technical Review)
// fall through to it because they expose no other matching keyword.
const COMPLIANCE_LOGOS = [
  ["essential", ASDEssentialEightLogo],
  ["cisa", CISALogo],
  ["cis", CISLogo],
  ["ens", ENSLogo],
  ["ffiec", FFIECLogo],
  ["fedramp", FedRAMPLogo],
  ["gdpr", GDPRLogo],
  ["gxp", GxPLogo],
  ["hipaa", HIPAALogo],
  ["iso", ISOLogo],
  ["mitre", MITRELogo],
  // `nist` comes before `nis2` because NIST 800-53 etc. would otherwise be
  // checked after `nis2`; both are unambiguous, but pinning the order avoids
  // surprises if a future id contains "nis2" inside a NIST acronym.
  ["nist", NISTLogo],
  ["nis2", NIS2Logo],
  ["pci", PCILogo],
  ["rbi", RBILogo],
  ["soc2", SOC2Logo],
  ["kisa", KISALogo],
  // `threatscore` (not `prowlerthreatscore`) matches both the framework name
  // `ProwlerThreatScore` (lowercased "prowlerthreatscore") AND the
  // compliance_id `prowler_threatscore_aws` (which separates the words with
  // an underscore). The previous one-word keyword silently failed for the
  // watchlist surface — only fixed in concert with moving `aws` to the end.
  ["threatscore", PROWLERTHREATLogo],
  ["c5", C5Logo],
  ["ccc", CCCLogo],
  ["csa", CSALogo],
  // DORA — universal framework (`prowler/compliance/dora.json`). The
  // compliance_id is just `dora`, no provider suffix.
  ["dora", DORALogo],
  ["secnumcloud", ANSSILogo],
  ["okta", OktaLogo],
  ["aws", AWSLogo],
] as const;

export const getComplianceIcon = (complianceTitle: string) => {
  const lowerTitle = complianceTitle.toLowerCase();
  return COMPLIANCE_LOGOS.find(([keyword]) =>
    lowerTitle.includes(keyword),
  )?.[1];
};
