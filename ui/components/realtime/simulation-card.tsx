import { Alert, AlertDescription, AlertTitle } from "@/components/shadcn/alert";
import {
  Card,
  CardContent,
  CardHeader,
  CardTitle,
} from "@/components/shadcn/card/card";
import { modeLabel } from "@/lib/realtime/display";
import {
  REALTIME_MODE,
  type RealtimeSimulationPayload,
} from "@/types/realtime";

function Outcome({ value, label }: { value: number; label: string }) {
  return (
    <div className="flex flex-col">
      <span className="text-text-neutral-primary text-3xl font-semibold tabular-nums">
        {value}
      </span>
      <span className="text-text-neutral-secondary text-sm">{label}</span>
    </div>
  );
}

/** What the current policy would do to today's open findings. Changes nothing. */
export function SimulationCard({
  simulation,
}: {
  simulation: RealtimeSimulationPayload;
}) {
  const {
    would_fix_in_account: fixes,
    would_propose_in_code: proposals,
    needs_a_person: manual,
  } = simulation;
  const isAuto = simulation.mode === REALTIME_MODE.AUTO;

  return (
    <Card variant="base" className="gap-4">
      <CardHeader>
        <CardTitle className="mt-0 text-base">
          If the policy ran today
        </CardTitle>
        <p className="text-text-neutral-tertiary text-sm">
          Based on {simulation.open} open finding
          {simulation.open === 1 ? "" : "s"} in mode{" "}
          <strong>{modeLabel(simulation.mode)}</strong>. This is a preview: it
          changes nothing.
        </p>
      </CardHeader>
      <CardContent className="flex flex-col gap-4">
        <div className="grid grid-cols-1 gap-4 sm:grid-cols-3">
          <Outcome value={fixes} label="fixed in the account" />
          <Outcome value={proposals} label="pull requests" />
          <Outcome value={manual} label="need a person" />
        </div>

        {simulation.outside_frameworks > 0 && (
          <p className="text-text-neutral-secondary text-sm">
            <strong>{simulation.outside_frameworks}</strong> outside the
            enforced frameworks: detected and alerted, never changed.
          </p>
        )}

        {simulation.open > 0 && (
          <p className="text-text-neutral-secondary text-sm">
            Automation would handle {simulation.automation_share}% of open
            findings, leaving {simulation.projected_open_after_auto} open after
            automatic fixes.
          </p>
        )}

        {simulation.effects.length > 0 && (
          <div className="flex flex-col gap-2">
            <h4 className="text-text-neutral-primary text-sm font-medium">
              What automatic fixes would do
            </h4>
            <ul className="flex flex-col gap-1">
              {simulation.effects.map((effect) => (
                <li
                  key={effect.check_id}
                  className="text-text-neutral-secondary text-sm"
                >
                  <code className="text-text-neutral-primary text-xs">
                    {effect.check_id}
                  </code>
                  : {effect.effect}{" "}
                  <span className="text-text-neutral-tertiary">
                    ({effect.resources} resource
                    {effect.resources === 1 ? "" : "s"})
                  </span>
                </li>
              ))}
            </ul>
          </div>
        )}

        {isAuto && simulation.dry_run && (
          <Alert variant="info">
            <AlertTitle>Dry run is on</AlertTitle>
            <AlertDescription>
              <p>
                Prowler Realtime records what it would change and changes
                nothing in your AWS account. Turn dry run off in the policy to
                apply fixes.
              </p>
            </AlertDescription>
          </Alert>
        )}
        {isAuto && !simulation.dry_run && (
          <Alert variant="warning">
            <AlertTitle>Dry run is off</AlertTitle>
            <AlertDescription>
              <p>
                With the policy enabled, these fixes are applied to your AWS
                account as soon as a matching change is detected.
              </p>
            </AlertDescription>
          </Alert>
        )}
        {!isAuto && (
          <p className="text-text-neutral-tertiary text-xs">
            Automatic fixes in the account are off in this mode, so none are
            counted. Switch the policy to Fix automatically to preview them.
          </p>
        )}
      </CardContent>
    </Card>
  );
}
