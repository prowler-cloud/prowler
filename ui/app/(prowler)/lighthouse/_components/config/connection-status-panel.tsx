import { AlertCircle, CheckCircle2, CircleDashed } from "lucide-react";

import {
  CONNECTION_STATUS,
  type ConnectionStatus,
  getAlertVariant,
  getConnectionStatusLabel,
} from "@/app/(prowler)/lighthouse/_lib/config";
import { formatLastChecked } from "@/app/(prowler)/lighthouse/_lib/format";
import { type LighthouseV2Configuration } from "@/app/(prowler)/lighthouse/_types";
import { Alert, AlertDescription, AlertTitle } from "@/components/shadcn/alert";

export function ConnectionStatusPanel({
  configuration,
  status,
}: {
  configuration?: LighthouseV2Configuration;
  status: ConnectionStatus;
}) {
  const statusText = getConnectionStatusLabel(status);
  const description =
    status === CONNECTION_STATUS.CONNECTED
      ? "Lighthouse can send messages with this provider."
      : status === CONNECTION_STATUS.FAILED
        ? "Connection failed. Review credentials and run another test."
        : "Connection has not been tested yet.";

  return (
    <Alert variant={getAlertVariant(status)}>
      {status === CONNECTION_STATUS.CONNECTED ? (
        <CheckCircle2 className="size-4" />
      ) : status === CONNECTION_STATUS.FAILED ? (
        <AlertCircle className="size-4" />
      ) : (
        <CircleDashed className="size-4" />
      )}
      <AlertTitle>{statusText}</AlertTitle>
      <AlertDescription>
        <p>{description}</p>
        <p>{formatLastChecked(configuration?.connectionLastCheckedAt)}</p>
      </AlertDescription>
    </Alert>
  );
}
