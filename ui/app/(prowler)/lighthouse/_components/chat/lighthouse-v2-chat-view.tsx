"use client";

import { type ReactNode, type SubmitEvent } from "react";

import {
  Conversation,
  ConversationContent,
  ConversationScrollButton,
} from "@/app/(prowler)/lighthouse/_components/ai-elements/conversation";
import { selectLighthouseChatCanSend } from "@/app/(prowler)/lighthouse/_lib/chat-store";
import { LIGHTHOUSE_V2_STREAM_STATUS } from "@/app/(prowler)/lighthouse/_lib/event-reducer";
import {
  buildLighthouseV2ModelSelectionValue,
  type LighthouseV2ModelSelection,
  parseLighthouseV2ModelSelectionValue,
} from "@/app/(prowler)/lighthouse/_lib/model-selection";
import {
  LIGHTHOUSE_V2_PROVIDER_TYPE,
  type LighthouseV2Configuration,
  type LighthouseV2ProviderType,
  type LighthouseV2SupportedModel,
  type LighthouseV2SupportedProvider,
} from "@/app/(prowler)/lighthouse/_types";
import { Card } from "@/components/shadcn";
import {
  Combobox,
  type ComboboxGroup,
} from "@/components/shadcn/combobox/combobox";
import { Skeleton } from "@/components/shadcn/skeleton/skeleton";

import { ProviderIcon } from "../config/provider-icon";
import { ChatComposerPanel } from "./composer";
import { ChatEmptyState } from "./empty-state";
import { useLighthouseChatStore } from "./lighthouse-chat-store-provider";
import { MessageBubble } from "./message-bubble";
import { StreamingAssistantMessage } from "./streaming-message";

export const LIGHTHOUSE_CHAT_SURFACE = {
  PAGE: "page",
  PANEL: "panel",
} as const;

export type LighthouseChatSurface =
  (typeof LIGHTHOUSE_CHAT_SURFACE)[keyof typeof LIGHTHOUSE_CHAT_SURFACE];

interface LighthouseV2ChatViewProps {
  surface: LighthouseChatSurface;
  emptyStateFooter?: ReactNode;
}

export function LighthouseV2ChatView({
  surface,
  emptyStateFooter,
}: LighthouseV2ChatViewProps) {
  // Whole-store subscription is intentional: the view renders most of the state and selectLighthouseChatCanSend takes full state.
  const state = useLighthouseChatStore((current) => current);
  const {
    config,
    messages,
    streamState,
    input,
    feedback,
    isLoadingSession,
    lastSubmittedText,
    selectedModelSelection,
    modelPreferenceSaving,
    setInput,
    dismissFeedback,
    selectModel,
    submitMessage,
  } = state;
  const { modelsByProvider, supportedProviders } = config;
  const connectedConfigurations = config.configurations.filter(
    (configuration) => configuration.connected === true,
  );

  const selectedConfiguration = selectedModelSelection
    ? connectedConfigurations.find(
        (configuration) =>
          configuration.providerType === selectedModelSelection.providerType,
      )
    : undefined;
  const modelSelectorGroups = buildModelSelectorGroups(
    connectedConfigurations,
    modelsByProvider,
    supportedProviders,
  );
  const showStaticOpenAIModel =
    isOnlyConnectedProvider(
      connectedConfigurations,
      LIGHTHOUSE_V2_PROVIDER_TYPE.OPENAI,
    ) &&
    selectedModelSelection?.providerType === LIGHTHOUSE_V2_PROVIDER_TYPE.OPENAI;
  const selectedModelLabel = selectedModelSelection
    ? getModelSelectionLabel(selectedModelSelection, modelsByProvider)
    : "No model selected";
  const selectedProviderName = selectedModelSelection
    ? getProviderDisplayName(
        selectedModelSelection.providerType,
        supportedProviders,
      )
    : "OpenAI";
  const selectedModelValue = selectedModelSelection
    ? buildLighthouseV2ModelSelectionValue(
        selectedModelSelection.providerType,
        selectedModelSelection.modelId,
      )
    : "";

  const canSend = selectLighthouseChatCanSend(state);

  const handleModelValueChange = (value: string) => {
    const selection = parseLighthouseV2ModelSelectionValue(value);
    if (!selection) return;
    void selectModel(selection);
  };

  const handleSubmit = (event: SubmitEvent<HTMLFormElement>) => {
    event.preventDefault();
    void submitMessage(input);
  };

  const hasLiveAssistantActivity =
    Boolean(streamState.activeTaskId) ||
    Boolean(streamState.assistantText) ||
    streamState.toolCalls.length > 0;
  const hasConversation = messages.length > 0 || hasLiveAssistantActivity;

  const composerPanelProps = {
    feedback,
    canRetry:
      streamState.status === LIGHTHOUSE_V2_STREAM_STATUS.DISCONNECTED &&
      lastSubmittedText !== null,
    onRetry: () =>
      lastSubmittedText ? void submitMessage(lastSubmittedText) : undefined,
    onDismissFeedback: dismissFeedback,
    canSend,
    input,
    isStreaming: Boolean(streamState.activeTaskId),
    modelSelector: showStaticOpenAIModel ? (
      <CurrentModelDisplay
        provider={selectedModelSelection.providerType}
        providerName={selectedProviderName}
        modelName={selectedModelLabel}
      />
    ) : (
      <div className="min-w-0 flex-1 sm:max-w-48">
        <Combobox
          aria-label="Model"
          value={selectedModelValue}
          onValueChange={handleModelValueChange}
          groups={modelSelectorGroups}
          disabled={modelSelectorGroups.length === 0 || modelPreferenceSaving}
          placeholder="Select model"
          searchPlaceholder="Search models..."
          emptyMessage="No models found."
          triggerClassName="h-8 text-sm"
        />
      </div>
    ),
    selectedConfigurationConnected: selectedConfiguration?.connected === true,
    onInputChange: setInput,
    onSubmit: handleSubmit,
    onSubmitText: submitMessage,
  };

  const chatBody = isLoadingSession ? (
    <SessionLoadingState />
  ) : hasConversation ? (
    <div className="flex min-h-0 flex-1 flex-col">
      <div className="relative flex min-h-0 flex-1 flex-col overflow-hidden">
        <Conversation className="h-full min-h-0">
          <ConversationContent
            className="mx-auto w-full max-w-4xl gap-5 px-4 pt-8 pb-20 md:px-8"
            scrollClassName="minimal-scrollbar overflow-x-hidden overflow-y-auto"
          >
            {messages.map((message) => (
              <MessageBubble key={message.id} message={message} />
            ))}
            {hasLiveAssistantActivity && (
              <StreamingAssistantMessage streamState={streamState} />
            )}
          </ConversationContent>
          <ConversationScrollButton className="z-20" />
        </Conversation>
        <div
          data-slot="lighthouse-v2-chat-scroll-fade"
          className="from-bg-neutral-secondary pointer-events-none absolute right-2 bottom-0 left-0 z-10 h-16 bg-gradient-to-t to-transparent"
        />
      </div>
      <div
        data-slot="lighthouse-v2-chat-composer-panel"
        className="bg-bg-neutral-secondary px-4 pb-5 md:px-8"
      >
        <div className="mx-auto w-full max-w-4xl">
          <ChatComposerPanel {...composerPanelProps} />
        </div>
      </div>
    </div>
  ) : (
    <ChatEmptyState
      {...composerPanelProps}
      footer={emptyStateFooter}
      compact={surface === LIGHTHOUSE_CHAT_SURFACE.PANEL}
    />
  );

  if (surface === LIGHTHOUSE_CHAT_SURFACE.PAGE) {
    return (
      <Card
        variant="base"
        className="flex h-full min-h-0 flex-col overflow-hidden"
      >
        {chatBody}
      </Card>
    );
  }

  return (
    <div className="bg-bg-neutral-secondary flex h-full min-h-0 flex-col overflow-hidden">
      {chatBody}
    </div>
  );
}

function SessionLoadingState() {
  return (
    <div
      aria-label="Loading conversation"
      className="flex min-h-0 flex-1 flex-col gap-4 px-4 pt-8 md:px-8"
    >
      <Skeleton className="h-10 w-2/3 self-end" />
      <Skeleton className="h-24 w-full" />
      <Skeleton className="h-10 w-1/2 self-end" />
      <Skeleton className="h-16 w-full" />
    </div>
  );
}

interface CurrentModelDisplayProps {
  provider: LighthouseV2ProviderType;
  providerName: string;
  modelName: string;
}

function CurrentModelDisplay({
  provider,
  providerName,
  modelName,
}: CurrentModelDisplayProps) {
  return (
    <div
      aria-label={`Current model: ${providerName} ${modelName}`}
      className="border-border-neutral-secondary bg-bg-neutral-secondary flex h-8 max-w-48 min-w-0 items-center gap-2 rounded-lg border px-2.5 text-sm"
    >
      <ProviderIcon
        provider={provider}
        className="text-text-neutral-secondary size-3.5 shrink-0"
      />
      <span className="text-text-neutral-tertiary shrink-0">
        {providerName}
      </span>
      <span className="text-text-neutral-primary min-w-0 truncate font-medium">
        {modelName}
      </span>
    </div>
  );
}

function buildModelSelectorGroups(
  connectedConfigurations: LighthouseV2Configuration[],
  modelsByProvider: Record<
    LighthouseV2ProviderType,
    LighthouseV2SupportedModel[]
  >,
  supportedProviders: LighthouseV2SupportedProvider[],
): ComboboxGroup[] {
  const groups: ComboboxGroup[] = [];

  for (const provider of supportedProviders) {
    const configuration = connectedConfigurations.find(
      (item) => item.providerType === provider.id,
    );
    if (!configuration) continue;

    const options = (modelsByProvider[configuration.providerType] ?? []).map(
      (model) => ({
        value: buildLighthouseV2ModelSelectionValue(
          configuration.providerType,
          model.id,
        ),
        label: model.name,
      }),
    );

    if (options.length === 0) continue;

    groups.push({
      heading: provider.name,
      options,
    });
  }

  return groups;
}

function isOnlyConnectedProvider(
  connectedConfigurations: LighthouseV2Configuration[],
  providerType: LighthouseV2ProviderType,
) {
  return (
    connectedConfigurations.length === 1 &&
    connectedConfigurations[0]?.providerType === providerType
  );
}

function getModelSelectionLabel(
  selection: LighthouseV2ModelSelection,
  modelsByProvider: Record<
    LighthouseV2ProviderType,
    LighthouseV2SupportedModel[]
  >,
) {
  return (
    modelsByProvider[selection.providerType]?.find(
      (model) => model.id === selection.modelId,
    )?.name ?? selection.modelId
  );
}

function getProviderDisplayName(
  providerType: LighthouseV2ProviderType,
  supportedProviders: LighthouseV2SupportedProvider[],
) {
  return (
    supportedProviders.find((provider) => provider.id === providerType)?.name ??
    providerType
  );
}
