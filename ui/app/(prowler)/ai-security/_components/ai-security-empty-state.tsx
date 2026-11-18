import { Bot } from "lucide-react";

import {
  StatusPanel,
  StatusPanelActions,
  StatusPanelBody,
  StatusPanelDescription,
  StatusPanelIcon,
  StatusPanelTitle,
} from "@/components/shadcn";

import { ConnectProviderButton } from "./connect-provider-button";

export const AiSecurityEmptyState = () => (
  <StatusPanel>
    <StatusPanelIcon>
      <Bot />
    </StatusPanelIcon>
    <StatusPanelBody>
      <StatusPanelTitle>No AI findings yet</StatusPanelTitle>
      <StatusPanelDescription>
        Add a Claude, OpenAI or ChatGPT provider, or scan an AWS account that
        uses Bedrock.
      </StatusPanelDescription>
    </StatusPanelBody>
    <StatusPanelActions>
      <ConnectProviderButton />
    </StatusPanelActions>
  </StatusPanel>
);
