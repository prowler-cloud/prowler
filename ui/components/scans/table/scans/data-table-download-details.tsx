import { Row } from "@tanstack/react-table";
import { useState } from "react";

import { DownloadIconButton, useToast } from "@/components/ui";
import { downloadScanZip } from "@/lib";

interface DataTableDownloadDetailsProps<ScanProps> {
  row: Row<ScanProps>;
}

export function DataTableDownloadDetails<ScanProps>({
  row,
}: DataTableDownloadDetailsProps<ScanProps>) {
  const { toast } = useToast();
  const [isDownloading, setIsDownloading] = useState(false);

  const scanId = (row.original as { id: string }).id;
  const scanState = (row.original as any).attributes?.state;

  const handleDownload = async () => {
    setIsDownloading(true);
    await downloadScanZip(scanId, toast);
    setIsDownloading(false);
  };

  return (
    <DownloadIconButton
      paramId={scanId}
      onDownload={handleDownload}
      isDownloading={isDownloading}
      isDisabled={scanState !== "completed"}
    />
  );
}
