import { Row } from "@tanstack/react-table";
import { useState } from "react";

import { DownloadIconButton, useToast } from "@/components/ui";
import { checkTaskStatus, downloadScanZip } from "@/lib";

interface DataTableDownloadDetailsProps<ScanProps> {
  row: Row<ScanProps>;
}

export function DataTableDownloadDetails<ScanProps>({
  row,
}: DataTableDownloadDetailsProps<ScanProps>) {
  const { toast } = useToast();
  const [isDownloading, setIsDownloading] = useState<boolean>(false);

  const scanId = (row.original as { id: string }).id;
  const taskId = (row.original as any).relationships?.task?.data?.id;
  const scanState = (row.original as any).attributes?.state;

  const handleDownload = async () => {
    setIsDownloading(true);
    const taskResult = await checkTaskStatus(taskId);

    if (taskResult.completed) {
      downloadScanZip(scanId, toast);
    } else {
      toast({
        variant: "destructive",
        title: "Download Failed",
        description: taskResult.error || "Unknown error",
      });
    }
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
