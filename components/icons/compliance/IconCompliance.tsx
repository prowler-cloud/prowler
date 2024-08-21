import AWSLogo from "./aws.svg";
import CISLogo from "./cis.svg";
import CISALogo from "./cisa.svg";
import ENSLogo from "./ens.png";
import FedRAMPLogo from "./fedramp.svg";
import FFIECLogo from "./ffiec.svg";
import GDPRLogo from "./gdpr.svg";
import GxPLogo from "./gxp-aws.svg";
import HIPAALogo from "./hipaa.svg";
import ISOLogo from "./iso-27001.svg";
import MITRELogo from "./mitre-attack.svg";
import NISTLogo from "./nist.svg";
import PCILogo from "./pci-dss.svg";
import RBILogo from "./rbi.svg";
import SOC2Logo from "./soc2.svg";

export const getComplianceIcon = (complianceTitle: string) => {
  if (complianceTitle.toLowerCase().includes("aws")) {
    return AWSLogo;
  }
  if (complianceTitle.toLowerCase().includes("cisa")) {
    return CISALogo;
  }
  if (complianceTitle.toLowerCase().includes("cis")) {
    return CISLogo;
  }
  if (complianceTitle.toLowerCase().includes("ens")) {
    return ENSLogo;
  }
  if (complianceTitle.toLowerCase().includes("ffiec")) {
    return FFIECLogo;
  }
  if (complianceTitle.toLowerCase().includes("fedramp")) {
    return FedRAMPLogo;
  }
  if (complianceTitle.toLowerCase().includes("gdpr")) {
    return GDPRLogo;
  }
  if (complianceTitle.toLowerCase().includes("gxp")) {
    return GxPLogo;
  }
  if (complianceTitle.toLowerCase().includes("hipaa")) {
    return HIPAALogo;
  }
  if (complianceTitle.toLowerCase().includes("iso")) {
    return ISOLogo;
  }
  if (complianceTitle.toLowerCase().includes("mitre")) {
    return MITRELogo;
  }
  if (complianceTitle.toLowerCase().includes("nist")) {
    return NISTLogo;
  }
  if (complianceTitle.toLowerCase().includes("pci")) {
    return PCILogo;
  }
  if (complianceTitle.toLowerCase().includes("rbi")) {
    return RBILogo;
  }
  if (complianceTitle.toLowerCase().includes("soc2")) {
    return SOC2Logo;
  }
};
