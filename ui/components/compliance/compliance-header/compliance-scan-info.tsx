import { Divider } from "@heroui/divider";
import { Tooltip } from "@heroui/tooltip";

import { DateWithTime, EntityInfo } from "@/components/ui/entities";
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
    <div className="flex items-center gap-4">
      <div className="flex shrink-0 items-center">
        <EntityInfo
          cloudProvider={scan.providerInfo.provider}
          entityAlias={scan.providerInfo.alias}
          entityId={scan.providerInfo.uid}
          showCopyAction={false}
          maxWidth="w-[80px]"
        />
      </div>
      <Divider orientation="vertical" className="h-8" />
      <div className="flex flex-col items-start whitespace-nowrap">
        <Tooltip
          content={scan.attributes.name || "- -"}
          placement="top"
          size="sm"
        >
          <p className="text-default-500 text-xs">
            {scan.attributes.name || "- -"}
          </p>
        </Tooltip>
        <DateWithTime inline dateTime={scan.attributes.completed_at} />
      </div>
    </div>
  );
};
