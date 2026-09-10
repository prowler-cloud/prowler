import { LighthouseContextContributor } from "@/components/lighthouse/context-contributor";
import {
  buildAlertSummaryContext,
  buildFocusedAlertContext,
} from "@/lib/lighthouse/context/contributions";

import type { AlertRule } from "../_types";

interface AlertsLighthouseContextProps {
  totalCount: number;
  editingAlert: AlertRule | null;
}

export const AlertsLighthouseContext = ({
  totalCount,
  editingAlert,
}: AlertsLighthouseContextProps) => {
  return (
    <>
      <LighthouseContextContributor
        contributorId="alerts-summary"
        item={buildAlertSummaryContext(totalCount)}
      />
      {editingAlert ? (
        <LighthouseContextContributor
          contributorId="alerts-editing-rule"
          item={buildFocusedAlertContext({
            id: editingAlert.id,
            name: editingAlert.attributes.name,
            trigger: editingAlert.attributes.trigger,
            enabled: editingAlert.attributes.enabled,
          })}
        />
      ) : null}
    </>
  );
};
