import { Divider } from "@nextui-org/react";
import React from "react";

import { DateWithTime, EntityInfoShort } from "@/components/ui/entities";

interface ComplianceScanInfoProps {
  scan: {
    providerInfo: {
      provider: "aws" | "azure" | "gcp" | "kubernetes";
      alias?: string;
      uid?: string;
    };
    attributes: {
      name?: string;
      completed_at: string;
    };
  };
}

export const ComplianceScanInfo: React.FC<ComplianceScanInfoProps> = ({
  scan,
}) => {
  return (
    <div className="flex w-fit items-center">
      <EntityInfoShort
        cloudProvider={scan.providerInfo.provider}
        entityAlias={scan.providerInfo.alias}
        entityId={scan.providerInfo.uid}
        hideCopyButton
      />
      <Divider orientation="vertical" className="mx-2 h-6" />
      <div className="flex flex-col items-start">
        <p className="text-xs text-default-500">
          {scan.attributes.name || "- -"}
        </p>
        <DateWithTime inline dateTime={scan.attributes.completed_at} />
      </div>
    </div>
  );
};
