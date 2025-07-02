import { Divider, Tooltip } from "@nextui-org/react";

import { DateWithTime, EntityInfoShort } from "@/components/ui/entities";
import { ProviderType } from "@/types";

interface ComplianceScanInfoProps {
  scan: {
    providerInfo: {
      provider: ProviderType;
      alias?: string;
      uid?: string;
    };
    attributes: {
      name?: string;
      completed_at: string;
    };
  };
}

export const ComplianceScanInfo = ({ scan }: ComplianceScanInfoProps) => {
  return (
    <div className="flex items-center gap-2">
      <EntityInfoShort
        cloudProvider={scan.providerInfo.provider}
        entityAlias={scan.providerInfo.alias}
        entityId={scan.providerInfo.uid}
        hideCopyButton
        snippetWidth="max-w-[100px]"
      />
      <Divider orientation="vertical" className="h-6" />
      <div className="flex flex-col items-start whitespace-nowrap">
        <Tooltip
          content={scan.attributes.name || "- -"}
          placement="top"
          size="sm"
        >
          <p className="text-xs text-default-500">
            {scan.attributes.name || "- -"}
          </p>
        </Tooltip>
        <DateWithTime inline dateTime={scan.attributes.completed_at} />
      </div>
    </div>
  );
};
