"use client";

import { type SubmitEvent, useRef, useState } from "react";

import {
  createLighthouseV2Session,
  getLighthouseV2Messages,
  sendLighthouseV2Message,
  updateLighthouseV2Configuration,
} from "@/app/(prowler)/lighthouse/_actions";
import {
  Conversation,
  ConversationContent,
  ConversationScrollButton,
} from "@/app/(prowler)/lighthouse/_components/ai-elements/conversation";
import {
  createInitialLighthouseV2StreamState,
  type LighthouseV2StreamState,
  reduceLighthouseV2Event,
} from "@/app/(prowler)/lighthouse/_lib/event-reducer";
import {
  buildOptimisticMessage,
  buildSessionTitle,
} from "@/app/(prowler)/lighthouse/_lib/messages";
import {
  buildLighthouseV2ModelSelectionValue,
  type LighthouseV2ModelSelection,
  parseLighthouseV2ModelSelectionValue,
} from "@/app/(prowler)/lighthouse/_lib/model-selection";
import {
  LIGHTHOUSE_V2_NEW_CHAT_EVENT,
  LIGHTHOUSE_V2_SESSION_ARCHIVED_EVENT,
  notifyLighthouseV2SessionsChanged,
} from "@/app/(prowler)/lighthouse/_lib/session-events";
import { parseStreamEvent } from "@/app/(prowler)/lighthouse/_lib/stream-event-parser";
import { buildLighthouseV2StreamUrl } from "@/app/(prowler)/lighthouse/_lib/stream-url";
import {
  LIGHTHOUSE_V2_PROVIDER_TYPE,
  LIGHTHOUSE_V2_SSE_EVENT,
  type LighthouseV2Configuration,
  type LighthouseV2Message,
  type LighthouseV2ProviderType,
  type LighthouseV2SSEEvent,
  type LighthouseV2SupportedModel,
  type LighthouseV2SupportedProvider,
} from "@/app/(prowler)/lighthouse/_types";
import { Card } from "@/components/shadcn";
import {
  Combobox,
  type ComboboxGroup,
} from "@/components/shadcn/combobox/combobox";
import { useMountEffect } from "@/hooks/use-mount-effect";

import { ProviderIcon } from "../config/provider-icon";
import { ChatComposerPanel } from "./composer";
import { ChatEmptyState } from "./empty-state";
import { MessageBubble } from "./message-bubble";
import { StreamingAssistantMessage } from "./streaming-message";

interface LighthouseV2ChatPageProps {
  configurations: LighthouseV2Configuration[];
  modelsByProvider: Record<
    LighthouseV2ProviderType,
    LighthouseV2SupportedModel[]
  >;
  supportedProviders: LighthouseV2SupportedProvider[];
  initialSessionId?: string;
  initialMessages: LighthouseV2Message[];
  initialPrompt?: string;
  initialError?: string;
}

export function LighthouseV2ChatPage({
  configurations,
  modelsByProvider,
  supportedProviders,
  initialSessionId,
  initialMessages,
  initialPrompt,
  initialError,
}: LighthouseV2ChatPageProps) {
  const eventSourceRef = useRef<EventSource | null>(null);
  const initialPromptSentRef = useRef(false);
  const connectedConfigurations = configurations.filter(
    (configuration) => configuration.connected === true,
  );
  const initialModelSelection = resolveInitialModelSelection(
    connectedConfigurations,
    modelsByProvider,
  );
  const [selectedModelSelection, setSelectedModelSelection] =
    useState<LighthouseV2ModelSelection | null>(initialModelSelection);
  const [modelPreferenceSaving, setModelPreferenceSaving] = useState(false);
  const [activeSessionId, setActiveSessionId] = useState<string | null>(
    initialSessionId ?? null,
  );
  // Mirror for window listeners registered on mount, whose closures would
  // otherwise keep the first render's activeSessionId.
  const activeSessionIdRef = useRef<string | null>(initialSessionId ?? null);
  const [messages, setMessages] = useState(initialMessages);
  const [input, setInput] = useState("");
  const [feedback, setFeedback] = useState<string | null>(initialError ?? null);
  const [blockedByConflict, setBlockedByConflict] = useState(false);
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [lastSubmittedText, setLastSubmittedText] = useState<string | null>(
    null,
  );
  const [streamState, setStreamState] = useState<LighthouseV2StreamState>(() =>
    createInitialLighthouseV2StreamState(),
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

  const canSend =
    selectedConfiguration?.connected === true &&
    Boolean(selectedModelSelection?.modelId) &&
    !streamState.activeTaskId &&
    !blockedByConflict &&
    !isSubmitting;

  const refreshMessages = async (sessionId: string): Promise<boolean> => {
    const result = await getLighthouseV2Messages(sessionId);
    // The fetch is async, so a reset (new chat, or archiving this session) can
    // land while it is in flight. Drop the stale result instead of repopulating
    // a chat that no longer points at this session.
    if (sessionId !== activeSessionIdRef.current) return false;
    if ("data" in result) {
      setMessages(result.data);
      return true;
    }
    return false;
  };

  const closeStream = () => {
    eventSourceRef.current?.close();
    eventSourceRef.current = null;
  };

  const handleTerminalEvent = async (
    sessionId: string,
    event: LighthouseV2SSEEvent,
  ) => {
    if (
      event.type === LIGHTHOUSE_V2_SSE_EVENT.MESSAGE_END ||
      event.type === LIGHTHOUSE_V2_SSE_EVENT.ERROR
    ) {
      closeStream();
      setBlockedByConflict(false);
      if (event.type === LIGHTHOUSE_V2_SSE_EVENT.ERROR) {
        setFeedback(event.detail || "Agent run failed.");
      }
      const refreshed = await refreshMessages(sessionId);
      if (refreshed) {
        setStreamState(createInitialLighthouseV2StreamState());
      }
      notifyLighthouseV2SessionsChanged();
    }
  };

  const startStream = (streamUrl: string, sessionId: string) => {
    closeStream();
    const source = new EventSource(streamUrl);
    eventSourceRef.current = source;

    const applyEvent = (event: LighthouseV2SSEEvent) => {
      setStreamState((current) => reduceLighthouseV2Event(current, event));
      void handleTerminalEvent(sessionId, event);
    };

    source.addEventListener("message.delta", (event) =>
      applyEvent(
        parseStreamEvent(event, LIGHTHOUSE_V2_SSE_EVENT.MESSAGE_DELTA),
      ),
    );
    source.addEventListener("tool_call.start", (event) =>
      applyEvent(
        parseStreamEvent(event, LIGHTHOUSE_V2_SSE_EVENT.TOOL_CALL_START),
      ),
    );
    source.addEventListener("tool_call.end", (event) =>
      applyEvent(
        parseStreamEvent(event, LIGHTHOUSE_V2_SSE_EVENT.TOOL_CALL_END),
      ),
    );
    source.addEventListener("message.end", (event) =>
      applyEvent(parseStreamEvent(event, LIGHTHOUSE_V2_SSE_EVENT.MESSAGE_END)),
    );
    source.addEventListener("error", (event) => {
      if (event instanceof MessageEvent) {
        applyEvent(parseStreamEvent(event, LIGHTHOUSE_V2_SSE_EVENT.ERROR));
      }
    });
    // The browser fires `onerror` both on a transient drop (it auto-reconnects)
    // and on a non-retryable failure such as a 401/404 on the SSE GET. Only the
    // latter leaves the source CLOSED, so surface a connection error there and
    // treat everything else as a reconnect.
    source.onerror = () => {
      if (eventSourceRef.current !== source) return;
      if (source.readyState === EventSource.CLOSED) {
        closeStream();
        setFeedback("Unable to connect to the response stream.");
      }
      setStreamState((current) =>
        reduceLighthouseV2Event(current, { type: "disconnect" }),
      );
    };
  };

  const ensureSession = async (text: string) => {
    if (activeSessionId) {
      return activeSessionId;
    }

    const title = buildSessionTitle(text);
    const result = await createLighthouseV2Session(title);
    if ("error" in result) {
      setFeedback(result.error);
      return null;
    }

    // Update the URL in place (not router.push) so the force-dynamic server
    // component is NOT re-run mid-submit. A re-run would change `key` in
    // page.tsx and remount this component, tearing down the open EventSource.
    replaceLighthouseV2SessionUrl(result.data.id);
    setActiveSessionId(result.data.id);
    activeSessionIdRef.current = result.data.id;
    notifyLighthouseV2SessionsChanged();
    return result.data.id;
  };

  const submitMessage = async (text: string) => {
    const trimmedText = text.trim();
    if (!trimmedText) return;
    if (!selectedModelSelection) {
      setFeedback("Select a model before sending a message.");
      return;
    }
    if (!canSend) return;

    setIsSubmitting(true);
    try {
      const sessionId = await ensureSession(trimmedText);
      if (!sessionId) return;

      const provisionalTaskId = `pending-${Date.now()}`;
      setFeedback(null);
      setBlockedByConflict(false);
      setLastSubmittedText(trimmedText);
      setInput("");
      setMessages((current) => [
        ...current,
        buildOptimisticMessage("user", trimmedText),
      ]);
      setStreamState(createInitialLighthouseV2StreamState(provisionalTaskId));

      // Subscribe to the same-origin SSE proxy BEFORE sending the message: the
      // backend has no replay buffer, so the listener must be attached before
      // the worker starts emitting.
      startStream(buildLighthouseV2StreamUrl(sessionId), sessionId);

      const result = await sendLighthouseV2Message({
        sessionId,
        text: trimmedText,
        provider: selectedModelSelection.providerType,
        model: selectedModelSelection.modelId,
      });

      if ("error" in result) {
        closeStream();
        setStreamState(createInitialLighthouseV2StreamState());
        setFeedback(result.error);
        if (result.status === 409) {
          setBlockedByConflict(true);
          await refreshMessages(sessionId);
        }
        return;
      }

      setStreamState((current) =>
        current.activeTaskId === provisionalTaskId
          ? { ...current, activeTaskId: result.data.task.id }
          : current,
      );
      notifyLighthouseV2SessionsChanged();
    } finally {
      setIsSubmitting(false);
    }
  };

  const handleModelValueChange = (value: string) => {
    const selection = parseLighthouseV2ModelSelectionValue(value);
    if (!selection) return;
    void handleModelSelectionChange(selection);
  };

  const handleModelSelectionChange = async (
    selection: LighthouseV2ModelSelection,
  ) => {
    // The selection drives the model used for the next message, so it stays
    // applied even if persisting it as the provider's default model fails —
    // reverting it would make a connected provider unusable when the save 4xxs.
    setSelectedModelSelection(selection);
    setFeedback(null);

    const configId = connectedConfigurations.find(
      (configuration) => configuration.providerType === selection.providerType,
    )?.id;
    if (!configId) return;

    setModelPreferenceSaving(true);

    const result = await updateLighthouseV2Configuration(configId, {
      defaultModel: selection.modelId,
    });

    setModelPreferenceSaving(false);

    if ("error" in result) {
      setFeedback(result.error);
    }
  };

  const handleSubmit = (event: SubmitEvent<HTMLFormElement>) => {
    event.preventDefault();
    void submitMessage(input);
  };

  // Close any open EventSource when the chat unmounts (e.g. route/session change).
  useMountEffect(() => {
    return () => closeStream();
  });

  useMountEffect(() => {
    if (initialPrompt && !initialPromptSentRef.current) {
      initialPromptSentRef.current = true;
      void submitMessage(initialPrompt);
    }
  });

  const resetToNewChat = () => {
    closeStream();
    setActiveSessionId(null);
    activeSessionIdRef.current = null;
    setMessages([]);
    setInput("");
    setFeedback(null);
    setBlockedByConflict(false);
    setIsSubmitting(false);
    setLastSubmittedText(null);
    setStreamState(createInitialLighthouseV2StreamState());
    replaceLighthouseV2SessionUrl(null);
  };

  // The sidebar "+" can't rely on routing to reset the latest conversation (its
  // URL was set via replaceState, invisible to Next's router), so reset in place.
  useMountEffect(() => {
    window.addEventListener(LIGHTHOUSE_V2_NEW_CHAT_EVENT, resetToNewChat);
    return () =>
      window.removeEventListener(LIGHTHOUSE_V2_NEW_CHAT_EVENT, resetToNewChat);
  });

  // Archiving deletes the session; when it's the open one, fall back to a new
  // chat instead of leaving a dead conversation and its URL on screen.
  useMountEffect(() => {
    const handleSessionArchived = (event: Event) => {
      const archivedId = (event as CustomEvent<{ sessionId: string }>).detail
        ?.sessionId;
      if (archivedId && archivedId === activeSessionIdRef.current) {
        resetToNewChat();
      }
    };

    window.addEventListener(
      LIGHTHOUSE_V2_SESSION_ARCHIVED_EVENT,
      handleSessionArchived,
    );
    return () =>
      window.removeEventListener(
        LIGHTHOUSE_V2_SESSION_ARCHIVED_EVENT,
        handleSessionArchived,
      );
  });

  const hasLiveAssistantActivity =
    Boolean(streamState.activeTaskId) ||
    Boolean(streamState.assistantText) ||
    streamState.toolCalls.length > 0;
  const hasConversation = messages.length > 0 || hasLiveAssistantActivity;

  const composerPanelProps = {
    feedback,
    canRetry:
      streamState.status === "disconnected" && lastSubmittedText !== null,
    onRetry: () =>
      lastSubmittedText ? void submitMessage(lastSubmittedText) : undefined,
    onDismissFeedback: () => setFeedback(null),
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

  return (
    <Card
      variant="base"
      className="flex h-full min-h-0 flex-col overflow-hidden"
    >
      {hasConversation ? (
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
        <ChatEmptyState {...composerPanelProps} />
      )}
    </Card>
  );
}

function replaceLighthouseV2SessionUrl(sessionId: string | null) {
  const url = sessionId
    ? `/lighthouse?session=${encodeURIComponent(sessionId)}`
    : "/lighthouse";

  window.history.replaceState(window.history.state, "", url);
}

function CurrentModelDisplay({
  provider,
  providerName,
  modelName,
}: {
  provider: LighthouseV2ProviderType;
  providerName: string;
  modelName: string;
}) {
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

// Fixed precedence used to pick which connected provider opens the chat. Any
// provider outside this list keeps its relative order behind these.
const LIGHTHOUSE_V2_PROVIDER_PRIORITY = [
  LIGHTHOUSE_V2_PROVIDER_TYPE.OPENAI,
  LIGHTHOUSE_V2_PROVIDER_TYPE.BEDROCK,
  LIGHTHOUSE_V2_PROVIDER_TYPE.OPENAI_COMPATIBLE,
] as const;

// Fallback model per provider when the configuration has no remembered model.
const LIGHTHOUSE_V2_PREFERRED_DEFAULT_MODEL: Partial<
  Record<LighthouseV2ProviderType, string>
> = {
  [LIGHTHOUSE_V2_PROVIDER_TYPE.OPENAI]: "gpt-5.5",
};

function resolveInitialModelSelection(
  connectedConfigurations: LighthouseV2Configuration[],
  modelsByProvider: Record<
    LighthouseV2ProviderType,
    LighthouseV2SupportedModel[]
  >,
): LighthouseV2ModelSelection | null {
  const priorityIndex = (providerType: LighthouseV2ProviderType) => {
    const index = LIGHTHOUSE_V2_PROVIDER_PRIORITY.indexOf(providerType);
    return index === -1 ? LIGHTHOUSE_V2_PROVIDER_PRIORITY.length : index;
  };
  // Stable sort keeps providers outside the priority list in their original order.
  const orderedConfigurations = [...connectedConfigurations].sort(
    (a, b) => priorityIndex(a.providerType) - priorityIndex(b.providerType),
  );

  for (const configuration of orderedConfigurations) {
    const providerModels = modelsByProvider[configuration.providerType] ?? [];
    if (providerModels.length === 0) continue;
    // Prefer the provider's remembered model when it is still supported, then
    // the provider's preferred default, then the first supported model.
    const rememberedModel = providerModels.find(
      (model) => model.id === configuration.defaultModel,
    );
    const preferredModel = providerModels.find(
      (model) =>
        model.id ===
        LIGHTHOUSE_V2_PREFERRED_DEFAULT_MODEL[configuration.providerType],
    );
    return {
      providerType: configuration.providerType,
      modelId: (rememberedModel ?? preferredModel ?? providerModels[0]).id,
    };
  }

  return null;
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
