"use client";

import { type SubmitEvent, useRef, useState } from "react";

import {
  cancelLighthouseV2Run,
  createLighthouseV2Session,
  getLighthouseV2Messages,
  sendLighthouseV2Message,
  updateLighthouseV2TenantConfiguration,
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
  notifyLighthouseV2SessionsChanged,
} from "@/app/(prowler)/lighthouse/_lib/session-events";
import { parseStreamEvent } from "@/app/(prowler)/lighthouse/_lib/stream-event-parser";
import { buildLighthouseV2StreamUrl } from "@/app/(prowler)/lighthouse/_lib/stream-url";
import {
  LIGHTHOUSE_V2_SSE_EVENT,
  type LighthouseV2Configuration,
  type LighthouseV2Message,
  type LighthouseV2ProviderType,
  type LighthouseV2SSEEvent,
  type LighthouseV2SupportedModel,
  type LighthouseV2TenantConfiguration,
} from "@/app/(prowler)/lighthouse/_types";
import { Card } from "@/components/shadcn";
import {
  Combobox,
  type ComboboxGroup,
} from "@/components/shadcn/combobox/combobox";
import { useMountEffect } from "@/hooks/use-mount-effect";

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
  tenantConfiguration?: LighthouseV2TenantConfiguration;
  initialSessionId?: string;
  initialMessages: LighthouseV2Message[];
  initialActiveTaskId?: string | null;
  initialStreamUrl?: string;
  initialPrompt?: string;
}

export function LighthouseV2ChatPage({
  configurations,
  modelsByProvider,
  tenantConfiguration,
  initialSessionId,
  initialMessages,
  initialActiveTaskId,
  initialStreamUrl,
  initialPrompt,
}: LighthouseV2ChatPageProps) {
  const eventSourceRef = useRef<EventSource | null>(null);
  const initialPromptSentRef = useRef(false);
  const connectedConfigurations = configurations.filter(
    (configuration) => configuration.connected === true,
  );
  const initialModelSelection = resolveInitialModelSelection(
    connectedConfigurations,
    modelsByProvider,
    tenantConfiguration,
  );
  const [selectedModelSelection, setSelectedModelSelection] =
    useState<LighthouseV2ModelSelection | null>(initialModelSelection);
  const [tenantModelDefaults, setTenantModelDefaults] = useState<
    Record<string, string>
  >(tenantConfiguration?.defaultModels ?? {});
  const [modelPreferenceSaving, setModelPreferenceSaving] = useState(false);
  const [activeSessionId, setActiveSessionId] = useState<string | null>(
    initialSessionId ?? null,
  );
  const [messages, setMessages] = useState(initialMessages);
  const [input, setInput] = useState("");
  const [feedback, setFeedback] = useState<string | null>(null);
  const [blockedByConflict, setBlockedByConflict] = useState(false);
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [lastSubmittedText, setLastSubmittedText] = useState<string | null>(
    null,
  );
  const [streamState, setStreamState] = useState<LighthouseV2StreamState>(() =>
    createInitialLighthouseV2StreamState(initialActiveTaskId ?? null),
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
  );
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
      event.type === LIGHTHOUSE_V2_SSE_EVENT.RUN_CANCELLED ||
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
    source.addEventListener("run.cancelled", (event) =>
      applyEvent(
        parseStreamEvent(event, LIGHTHOUSE_V2_SSE_EVENT.RUN_CANCELLED),
      ),
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
    // applied even if persisting it as the tenant default fails. Only the
    // saved-default mirror is rolled back on failure — reverting the active
    // selection would make a connected provider unusable when the save 4xxs.
    const previousDefaults = tenantModelDefaults;

    setSelectedModelSelection(selection);
    setFeedback(null);

    const nextDefaults = {
      ...tenantModelDefaults,
      [selection.providerType]: selection.modelId,
    };
    setTenantModelDefaults(nextDefaults);
    setModelPreferenceSaving(true);

    const result = await updateLighthouseV2TenantConfiguration({
      defaultProvider: selection.providerType,
      defaultModels: nextDefaults,
    });

    setModelPreferenceSaving(false);

    if ("error" in result) {
      setTenantModelDefaults(previousDefaults);
      setFeedback(result.error);
      return;
    }

    setTenantModelDefaults(result.data.defaultModels);
  };

  const handleSubmit = (event: SubmitEvent<HTMLFormElement>) => {
    event.preventDefault();
    void submitMessage(input);
  };

  const handleStop = async () => {
    if (!activeSessionId || !streamState.activeTaskId) return;
    const taskId = streamState.activeTaskId;
    const result = await cancelLighthouseV2Run(activeSessionId, taskId);
    closeStream();
    setStreamState((current) =>
      reduceLighthouseV2Event(current, {
        type: "run.cancelled",
        taskId,
      }),
    );
    setBlockedByConflict(false);
    await refreshMessages(activeSessionId);
    notifyLighthouseV2SessionsChanged();
    if ("error" in result) {
      setFeedback(result.error);
    }
  };

  useMountEffect(() => {
    if (initialSessionId && initialActiveTaskId && initialStreamUrl) {
      startStream(initialStreamUrl, initialSessionId);
    }

    return () => closeStream();
  });

  useMountEffect(() => {
    if (initialPrompt && !initialPromptSentRef.current) {
      initialPromptSentRef.current = true;
      void submitMessage(initialPrompt);
    }
  });

  // The sidebar "+" can't rely on routing to reset the latest conversation (its
  // URL was set via replaceState, invisible to Next's router), so reset in place.
  useMountEffect(() => {
    const resetToNewChat = () => {
      closeStream();
      setActiveSessionId(null);
      setMessages([]);
      setInput("");
      setFeedback(null);
      setBlockedByConflict(false);
      setIsSubmitting(false);
      setLastSubmittedText(null);
      setStreamState(createInitialLighthouseV2StreamState());
      replaceLighthouseV2SessionUrl(null);
    };

    window.addEventListener(LIGHTHOUSE_V2_NEW_CHAT_EVENT, resetToNewChat);
    return () =>
      window.removeEventListener(LIGHTHOUSE_V2_NEW_CHAT_EVENT, resetToNewChat);
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
    modelSelector: (
      <div className="min-w-0 flex-1 sm:max-w-80">
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
    onStop: handleStop,
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

function resolveInitialModelSelection(
  connectedConfigurations: LighthouseV2Configuration[],
  modelsByProvider: Record<
    LighthouseV2ProviderType,
    LighthouseV2SupportedModel[]
  >,
  tenantConfiguration?: LighthouseV2TenantConfiguration,
): LighthouseV2ModelSelection | null {
  const tenantDefaultProvider = tenantConfiguration?.defaultProvider;

  if (tenantDefaultProvider) {
    const defaultModel =
      tenantConfiguration.defaultModels[tenantDefaultProvider];
    if (
      defaultModel &&
      hasConnectedModel(
        connectedConfigurations,
        modelsByProvider,
        tenantDefaultProvider,
        defaultModel,
      )
    ) {
      return {
        providerType: tenantDefaultProvider,
        modelId: defaultModel,
      };
    }
  }

  for (const configuration of connectedConfigurations) {
    const providerModels = modelsByProvider[configuration.providerType] ?? [];
    const savedModel =
      tenantConfiguration?.defaultModels[configuration.providerType];
    const model =
      providerModels.find((candidate) => candidate.id === savedModel) ??
      providerModels[0];

    if (model) {
      return {
        providerType: configuration.providerType,
        modelId: model.id,
      };
    }
  }

  return null;
}

function hasConnectedModel(
  connectedConfigurations: LighthouseV2Configuration[],
  modelsByProvider: Record<
    LighthouseV2ProviderType,
    LighthouseV2SupportedModel[]
  >,
  providerType: LighthouseV2ProviderType,
  modelId: string,
) {
  return (
    connectedConfigurations.some(
      (configuration) => configuration.providerType === providerType,
    ) &&
    (modelsByProvider[providerType] ?? []).some((model) => model.id === modelId)
  );
}

function buildModelSelectorGroups(
  connectedConfigurations: LighthouseV2Configuration[],
  modelsByProvider: Record<
    LighthouseV2ProviderType,
    LighthouseV2SupportedModel[]
  >,
): ComboboxGroup[] {
  return connectedConfigurations
    .map((configuration) => ({
      heading: getLighthouseV2ProviderLabel(configuration.providerType),
      options: (modelsByProvider[configuration.providerType] ?? []).map(
        (model) => ({
          value: buildLighthouseV2ModelSelectionValue(
            configuration.providerType,
            model.id,
          ),
          label: model.id,
        }),
      ),
    }))
    .filter((group) => group.options.length > 0);
}

function getLighthouseV2ProviderLabel(providerType: LighthouseV2ProviderType) {
  return LIGHTHOUSE_V2_PROVIDER_LABELS[providerType] ?? providerType;
}

const LIGHTHOUSE_V2_PROVIDER_LABELS = {
  openai: "OpenAI",
  bedrock: "Amazon Bedrock",
  "openai-compatible": "OpenAI Compatible",
} as const satisfies Record<LighthouseV2ProviderType, string>;
