import { actorParts } from "@/app/(prowler)/realtime/_lib/display";

import { FitText } from "./fit-text";

interface ActorCellProps {
  arn: string;
}

/** Who made the call, then the role they used; the full ARN on hover. */
export function ActorCell({ arn }: ActorCellProps) {
  const { name, via } = actorParts(arn);
  return (
    <div className="flex min-w-0 flex-col gap-0.5" title={arn}>
      <FitText className="text-text-neutral-secondary font-mono text-xs">
        {name}
      </FitText>
      {via && (
        <FitText className="text-text-neutral-tertiary text-xs">{via}</FitText>
      )}
    </div>
  );
}
