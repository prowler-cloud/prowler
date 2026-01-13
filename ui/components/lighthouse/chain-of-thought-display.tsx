/**
 * ChainOfThoughtDisplay component
 * Displays tool execution progress for Lighthouse assistant messages
 */

import { CheckCircle2 } from "lucide-react";

import {
  ChainOfThought,
  ChainOfThoughtContent,
  ChainOfThoughtHeader,
  ChainOfThoughtStep,
} from "@/components/ai-elements/chain-of-thought";
import {
  CHAIN_OF_THOUGHT_ACTIONS,
  type ChainOfThoughtEvent,
  getChainOfThoughtHeaderText,
  getChainOfThoughtStepLabel,
  isMetaTool,
} from "@/components/lighthouse/chat-utils";

interface ChainOfThoughtDisplayProps {
  events: ChainOfThoughtEvent[];
  isStreaming: boolean;
  messageKey: string;
}

export function ChainOfThoughtDisplay({
  events,
  isStreaming,
  messageKey,
}: ChainOfThoughtDisplayProps) {
  if (events.length === 0) {
    return null;
  }

  const headerText = getChainOfThoughtHeaderText(isStreaming, events);

  return (
    <div className="mb-4">
      <ChainOfThought defaultOpen={false}>
        <ChainOfThoughtHeader>{headerText}</ChainOfThoughtHeader>
        <ChainOfThoughtContent>
          {events.map((event, eventIdx) => {
            const { action, metaTool, tool } = event;

            // Only show tool_complete events (skip planning and start)
            if (action !== CHAIN_OF_THOUGHT_ACTIONS.COMPLETE) {
              return null;
            }

            // Skip actual tool execution events (only show meta-tools)
            if (!isMetaTool(metaTool)) {
              return null;
            }

            const label = getChainOfThoughtStepLabel(metaTool, tool);

            return (
              <ChainOfThoughtStep
                key={`${messageKey}-cot-${eventIdx}`}
                icon={CheckCircle2}
                label={label}
                status="complete"
              />
            );
          })}
        </ChainOfThoughtContent>
      </ChainOfThought>
    </div>
  );
}
