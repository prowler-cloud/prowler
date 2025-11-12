"use client";

import Image from "next/image";

import AWSLogo from "@/components/icons/compliance/aws.svg";
import CISLogo from "@/components/icons/compliance/cis.svg";
import ISOLogo from "@/components/icons/compliance/iso-27001.svg";
import NISTLogo from "@/components/icons/compliance/nist.svg";
import PCILogo from "@/components/icons/compliance/pci-dss.svg";
import SOC2Logo from "@/components/icons/compliance/soc2.svg";

import { WatchlistCard, WatchlistItem } from "./watchlist-card";

const ComplianceIcon = ({ src }: { src: string }) => (
  <div className="relative size-3">
    <Image
      src={src}
      alt="Compliance framework"
      fill
      className="object-contain"
    />
  </div>
);

const MOCK_COMPLIANCE_ITEMS: WatchlistItem[] = [
  {
    key: "nist-cif",
    icon: <ComplianceIcon src={NISTLogo} />,
    label: "NIST CIF - 1.1",
    value: "10%",
  },
  {
    key: "iso-27001",
    icon: <ComplianceIcon src={ISOLogo} />,
    label: "ISO 27001 - 2022",
    value: "51%",
  },
  {
    key: "pci-4.0",
    icon: <ComplianceIcon src={PCILogo} />,
    label: "PCI - 4.0",
    value: "12%",
  },
  {
    key: "cis-5.0",
    icon: <ComplianceIcon src={CISLogo} />,
    label: "CIS - 5.0",
    value: "78%",
  },
  {
    key: "soc-2",
    icon: <ComplianceIcon src={SOC2Logo} />,
    label: "SOC 2",
    value: "82%",
  },
  {
    key: "aws-well-architected-framework",
    icon: <ComplianceIcon src={AWSLogo} />,
    label: "AWS Well-Architected Framework",
    value: "90%",
  },
];

export const ComplianceWatchlist = () => {
  const items = MOCK_COMPLIANCE_ITEMS;

  return (
    <WatchlistCard
      title="Compliance Watchlist"
      items={items}
      ctaLabel="Compliance Dashboard"
      ctaHref="/compliance"
      emptyState={{
        message: "This space is looking empty.",
        description: "to add compliance frameworks to your watchlist.",
        linkText: "Compliance Dashboard",
      }}
    />
  );
};
