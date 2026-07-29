import { AlertCircle, CheckCircle2, CircleDashed } from "lucide-react";

import {
  CONNECTION_STATUS,
  type ConnectionStatus,
} from "@/app/(prowler)/lighthouse/_lib/config";
import { Badge } from "@/components/shadcn/badge/badge";

export function StatusBadge({ status }: { status: ConnectionStatus }) {
  if (status === CONNECTION_STATUS.CONNECTED) {
    return (
      <Badge variant="success">
        <CheckCircle2 />
        Connected
      </Badge>
    );
  }

  if (status === CONNECTION_STATUS.FAILED) {
    return (
      <Badge variant="error">
        <AlertCircle />
        Failed
      </Badge>
    );
  }

  return (
    <Badge variant="outline">
      <CircleDashed />
      Not tested
    </Badge>
  );
}
