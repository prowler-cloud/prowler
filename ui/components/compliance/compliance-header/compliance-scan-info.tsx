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
    <div className="flex w-full items-center gap-2">
      <div className="flex min-w-0 basis-1/2 items-center overflow-hidden">
        <EntityInfo
          cloudProvider={scan.providerInfo.provider}
          entityAlias={scan.providerInfo.alias}
          entityId={scan.providerInfo.uid}
          showCopyAction={false}
        />
      </div>
      <Divider orientation="vertical" className="h-8 shrink-0" />
      <div className="flex min-w-0 basis-1/2 flex-col items-start overflow-hidden">
        <Tooltip
          content={scan.attributes.name || "- -"}
          placement="top"
          size="sm"
        >
          <p className="text-default-500 truncate text-xs">
            {scan.attributes.name || "- -"}
          </p>
        </Tooltip>
        <DateWithTime inline dateTime={scan.attributes.completed_at} />
      </div>
    </div>
  );
};
