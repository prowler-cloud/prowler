"use client";

import { Bot, Loader2, Send, Square, UserRound } from "lucide-react";
import { useRouter } from "next/navigation";
import { type FormEvent, useRef, useState } from "react";

import {
  archiveLighthouseV2Session,
  cancelLighthouseV2Run,
  createLighthouseV2Session,
  getLighthouseV2Messages,
  getLighthouseV2Sessions,
  sendLighthouseV2Message,
} from "@/actions/lighthouse-v2/lighthouse-v2";
import {
  Conversation,
  ConversationContent,
  ConversationEmptyState,
  ConversationScrollButton,
} from "@/components/ai-elements/conversation";
import { Button } from "@/components/shadcn/button/button";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/shadcn/select/select";
import { Textarea } from "@/components/shadcn/textarea/textarea";
import { useMountEffect } from "@/hooks/use-mount-effect";
import {
  createInitialLighthouseV2StreamState,
  type LighthouseV2StreamState,
  reduceLighthouseV2Event,
} from "@/lib/lighthouse-v2/event-reducer";
import { cn } from "@/lib/utils";
import {
  LIGHTHOUSE_V2_MESSAGE_ROLE,
  LIGHTHOUSE_V2_PART_TYPE,
  LIGHTHOUSE_V2_PROVIDER_TYPE,
  LIGHTHOUSE_V2_SSE_EVENT,
  type LighthouseV2Configuration,
  type LighthouseV2Message,
  type LighthouseV2ProviderType,
  type LighthouseV2Session,
  type LighthouseV2SSEEvent,
  type LighthouseV2SupportedModel,
} from "@/types/lighthouse-v2";

import { LighthouseV2SessionHistory } from "../history";

interface LighthouseV2ChatPageProps {
  configurations: LighthouseV2Configuration[];
  modelsByProvider: Record<
    LighthouseV2ProviderType,
    LighthouseV2SupportedModel[]
  >;
  sessions: LighthouseV2Session[];
  initialSessionId?: string;
  initialMessages: LighthouseV2Message[];
  initialPrompt?: string;
  showHistory?: boolean;
}

export function LighthouseV2ChatPage({
  configurations,
  modelsByProvider,
  sessions,
  initialSessionId,
  initialMessages,
  initialPrompt,
  showHistory = true,
}: LighthouseV2ChatPageProps) {
  const router = useRouter();
  const eventSourceRef = useRef<EventSource | null>(null);
  const initialPromptSentRef = useRef(false);
  const connectedConfigurations = configurations.filter(
    (configuration) => configuration.connected === true,
  );
  const initialProvider =
    connectedConfigurations[0]?.providerType ??
    configurations[0]?.providerType ??
    LIGHTHOUSE_V2_PROVIDER_TYPE.OPENAI;
  const [selectedProvider, setSelectedProvider] =
    useState<LighthouseV2ProviderType>(initialProvider);
  const [selectedModel, setSelectedModel] = useState(
    connectedConfigurations[0]?.defaultModel ??
      modelsByProvider[initialProvider]?.[0]?.id ??
      "",
  );
  const [localSessions, setLocalSessions] = useState(sessions);
  const [activeSessionId, setActiveSessionId] = useState<string | null>(
    initialSessionId ?? null,
  );
  const [messages, setMessages] = useState(initialMessages);
  const [input, setInput] = useState("");
  const [search, setSearch] = useState("");
  const [feedback, setFeedback] = useState<string | null>(null);
  const [blockedByConflict, setBlockedByConflict] = useState(false);
  const [lastSubmittedText, setLastSubmittedText] = useState<string | null>(
    null,
  );
  const [streamState, setStreamState] = useState<LighthouseV2StreamState>(() =>
    createInitialLighthouseV2StreamState(),
  );

  const selectedConfiguration = configurations.find(
    (configuration) => configuration.providerType === selectedProvider,
  );
  const providerModels = modelsByProvider[selectedProvider] ?? [];
  const canSend =
    selectedConfiguration?.connected === true &&
    !streamState.activeTaskId &&
    !blockedByConflict;

  const handleProviderChange = (provider: LighthouseV2ProviderType) => {
    const nextConfig = configurations.find(
      (configuration) => configuration.providerType === provider,
    );
    setSelectedProvider(provider);
    setSelectedModel(
      nextConfig?.defaultModel ?? modelsByProvider[provider]?.[0]?.id ?? "",
    );
  };

  const refreshMessages = async (sessionId: string) => {
    const result = await getLighthouseV2Messages(sessionId);
    if ("data" in result) {
      setMessages(result.data);
    }
  };

  const refreshSessions = async (nextSearch = search) => {
    const result = await getLighthouseV2Sessions(
      nextSearch ? { search: nextSearch } : undefined,
    );
    if ("data" in result) {
      setLocalSessions(result.data);
    }
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
      await refreshMessages(sessionId);
      await refreshSessions();
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
    source.onerror = () => {
      closeStream();
      setStreamState((current) =>
        reduceLighthouseV2Event(current, { type: "disconnect" }),
      );
      void refreshMessages(sessionId);
      setFeedback("Stream disconnected. Messages were refreshed.");
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

    setActiveSessionId(result.data.id);
    setLocalSessions((current) => [result.data, ...current]);
    router.push(`/lighthouse?session=${encodeURIComponent(result.data.id)}`);
    return result.data.id;
  };

  const submitMessage = async (text: string) => {
    const trimmedText = text.trim();
    if (!trimmedText || !canSend) return;

    const sessionId = await ensureSession(trimmedText);
    if (!sessionId) return;

    setFeedback(null);
    setBlockedByConflict(false);
    setLastSubmittedText(trimmedText);
    setInput("");
    setMessages((current) => [
      ...current,
      buildOptimisticMessage("user", trimmedText),
    ]);

    const result = await sendLighthouseV2Message({
      sessionId,
      text: trimmedText,
      provider: selectedProvider,
      model: selectedModel || null,
    });

    if ("error" in result) {
      setFeedback(result.error);
      if (result.status === 409) {
        setBlockedByConflict(true);
        await refreshMessages(sessionId);
      }
      return;
    }

    setStreamState(createInitialLighthouseV2StreamState(result.data.task.id));
    if (result.data.streamUrl) {
      startStream(result.data.streamUrl, sessionId);
    }
    await refreshSessions();
  };

  const handleSubmit = (event: FormEvent<HTMLFormElement>) => {
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
    if ("error" in result) {
      setFeedback(result.error);
    }
  };

  const handleOpenSession = async (sessionId: string) => {
    closeStream();
    setActiveSessionId(sessionId);
    setStreamState(createInitialLighthouseV2StreamState());
    setBlockedByConflict(false);
    setFeedback(null);
    router.push(`/lighthouse?session=${encodeURIComponent(sessionId)}`);
    await refreshMessages(sessionId);
  };

  const handleNewSession = () => {
    closeStream();
    setActiveSessionId(null);
    setMessages([]);
    setInput("");
    setFeedback(null);
    setBlockedByConflict(false);
    setStreamState(createInitialLighthouseV2StreamState());
    router.push("/lighthouse");
  };

  const handleArchiveSession = async (sessionId: string) => {
    const result = await archiveLighthouseV2Session(sessionId);
    if ("error" in result) {
      setFeedback(result.error);
      return;
    }
    setLocalSessions((current) =>
      current.filter((session) => session.id !== sessionId),
    );
    if (sessionId === activeSessionId) {
      handleNewSession();
    }
  };

  const handleSearchChange = (value: string) => {
    setSearch(value);
    void refreshSessions(value);
  };

  useMountEffect(() => {
    if (initialPrompt && !initialPromptSentRef.current) {
      initialPromptSentRef.current = true;
      void submitMessage(initialPrompt);
    }
  });

  return (
    <div className="grid h-full min-h-0 gap-4 lg:grid-cols-[300px_1fr]">
      {showHistory && (
        <LighthouseV2SessionHistory
          sessions={localSessions}
          activeSessionId={activeSessionId}
          search={search}
          onSearchChange={handleSearchChange}
          onNewSession={handleNewSession}
          onOpenSession={handleOpenSession}
          onArchiveSession={handleArchiveSession}
        />
      )}

      <section className="border-border-neutral-secondary bg-bg-neutral-secondary flex min-h-0 flex-col rounded-[8px] border">
        <Conversation className="min-h-0">
          <ConversationContent>
            {messages.length === 0 && !streamState.assistantText ? (
              <ConversationEmptyState title="Lighthouse" description="" />
            ) : (
              <>
                {messages.map((message) => (
                  <MessageBubble key={message.id} message={message} />
                ))}
                {streamState.assistantText && (
                  <StreamingAssistantMessage streamState={streamState} />
                )}
              </>
            )}
          </ConversationContent>
          <ConversationScrollButton />
        </Conversation>

        <div className="border-border-neutral-secondary border-t p-3">
          {feedback && (
            <div className="border-border-neutral-secondary mb-2 flex items-center justify-between gap-3 rounded-[8px] border px-3 py-2 text-sm">
              <span>{feedback}</span>
              {streamState.status === "disconnected" && lastSubmittedText && (
                <Button
                  type="button"
                  variant="outline"
                  size="sm"
                  onClick={() => submitMessage(lastSubmittedText)}
                >
                  Retry
                </Button>
              )}
            </div>
          )}

          <div className="mb-2 flex flex-wrap gap-2">
            <Select
              value={selectedProvider}
              onValueChange={(value) =>
                handleProviderChange(value as LighthouseV2ProviderType)
              }
            >
              <SelectTrigger className="h-9 w-[180px]">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                {configurations.map((configuration) => (
                  <SelectItem
                    key={configuration.providerType}
                    value={configuration.providerType}
                    disabled={configuration.connected !== true}
                  >
                    {configuration.providerType}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
            <Select value={selectedModel} onValueChange={setSelectedModel}>
              <SelectTrigger className="h-9 min-w-[220px]">
                <SelectValue placeholder="Model" />
              </SelectTrigger>
              <SelectContent width="wide">
                {providerModels.map((model) => (
                  <SelectItem key={model.id} value={model.id}>
                    {model.id}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>

          <form className="flex items-end gap-2" onSubmit={handleSubmit}>
            <Textarea
              aria-label="Message"
              value={input}
              onChange={(event) => setInput(event.target.value)}
              disabled={!canSend}
              placeholder={
                selectedConfiguration?.connected === true
                  ? "Ask Lighthouse"
                  : "Connect a provider first"
              }
              className="max-h-40 min-h-12 flex-1"
              onKeyDown={(event) => {
                if (event.key === "Enter" && !event.shiftKey) {
                  event.preventDefault();
                  void submitMessage(input);
                }
              }}
            />
            {streamState.activeTaskId ? (
              <Button type="button" variant="outline" onClick={handleStop}>
                <Square />
                Stop
              </Button>
            ) : (
              <Button type="submit" disabled={!canSend || !input.trim()}>
                <Send />
                Send
              </Button>
            )}
          </form>
        </div>
      </section>
    </div>
  );
}

function MessageBubble({ message }: { message: LighthouseV2Message }) {
  const isUser = message.role === LIGHTHOUSE_V2_MESSAGE_ROLE.USER;
  return (
    <article
      className={cn("flex gap-3", isUser ? "justify-end" : "justify-start")}
    >
      {!isUser && <Bot className="text-text-neutral-tertiary mt-1 size-5" />}
      <div
        className={cn(
          "max-w-[min(760px,85%)] rounded-[8px] px-4 py-3 text-sm",
          isUser
            ? "bg-button-primary text-black"
            : "bg-bg-neutral-tertiary text-text-neutral-primary",
        )}
      >
        {message.parts.map((part) => (
          <div key={part.id || `${message.id}-${part.type}`}>
            {part.type === LIGHTHOUSE_V2_PART_TYPE.TEXT ? (
              <p className="whitespace-pre-wrap">
                {getTextContent(part.content)}
              </p>
            ) : (
              <p className="text-text-neutral-secondary text-xs">{part.type}</p>
            )}
          </div>
        ))}
      </div>
      {isUser && (
        <UserRound className="text-text-neutral-tertiary mt-1 size-5" />
      )}
    </article>
  );
}

function StreamingAssistantMessage({
  streamState,
}: {
  streamState: LighthouseV2StreamState;
}) {
  return (
    <article className="flex justify-start gap-3">
      <Bot className="text-text-neutral-tertiary mt-1 size-5" />
      <div className="bg-bg-neutral-tertiary text-text-neutral-primary max-w-[min(760px,85%)] rounded-[8px] px-4 py-3 text-sm">
        <p className="whitespace-pre-wrap">{streamState.assistantText}</p>
        {streamState.toolCalls.length > 0 && (
          <div className="mt-3 grid gap-1">
            {streamState.toolCalls.map((toolCall) => (
              <div
                key={toolCall.id}
                className="text-text-neutral-secondary flex items-center gap-2 text-xs"
              >
                {toolCall.status === "running" && (
                  <Loader2 className="size-3 animate-spin" />
                )}
                <span>{toolCall.name}</span>
                {toolCall.outcome && <span>{toolCall.outcome}</span>}
              </div>
            ))}
          </div>
        )}
      </div>
    </article>
  );
}

function parseStreamEvent(
  event: Event,
  type: LighthouseV2SSEEvent["type"],
): LighthouseV2SSEEvent {
  const data = event instanceof MessageEvent ? parseJsonObject(event.data) : {};

  if (type === LIGHTHOUSE_V2_SSE_EVENT.MESSAGE_DELTA) {
    return {
      type,
      content: readString(data, "content"),
    };
  }
  if (type === LIGHTHOUSE_V2_SSE_EVENT.TOOL_CALL_START) {
    return {
      type,
      toolCallId: readString(data, "tool_call_id"),
      toolName: readString(data, "tool_name"),
    };
  }
  if (type === LIGHTHOUSE_V2_SSE_EVENT.TOOL_CALL_END) {
    return {
      type,
      toolCallId: readString(data, "tool_call_id"),
      outcome: readString(data, "outcome"),
    };
  }
  if (type === LIGHTHOUSE_V2_SSE_EVENT.MESSAGE_END) {
    return {
      type,
      messageId: readString(data, "message_id"),
    };
  }
  if (type === LIGHTHOUSE_V2_SSE_EVENT.RUN_CANCELLED) {
    return {
      type,
      taskId: readString(data, "task_id"),
    };
  }
  return {
    type: LIGHTHOUSE_V2_SSE_EVENT.ERROR,
    code: readString(data, "code"),
    detail: readString(data, "detail"),
  };
}

function buildOptimisticMessage(
  role: "user" | "assistant",
  text: string,
): LighthouseV2Message {
  const now = new Date().toISOString();
  const id = `optimistic-${role}-${now}`;
  return {
    id,
    role,
    model: null,
    tokenUsage: null,
    insertedAt: now,
    parts: [
      {
        id: `${id}-part`,
        type: LIGHTHOUSE_V2_PART_TYPE.TEXT,
        content: { text },
        toolCallOutcome: null,
        insertedAt: now,
        updatedAt: now,
      },
    ],
  };
}

function buildSessionTitle(text: string): string {
  const normalized = text.replace(/\s+/g, " ").trim();
  return normalized.length > 80 ? `${normalized.slice(0, 77)}...` : normalized;
}

function getTextContent(content: unknown): string {
  if (typeof content === "string") {
    return content;
  }
  if (
    typeof content === "object" &&
    content !== null &&
    "text" in content &&
    typeof content.text === "string"
  ) {
    return content.text;
  }
  return "";
}

function parseJsonObject(value: unknown): Record<string, unknown> {
  if (typeof value !== "string") {
    return {};
  }
  try {
    const parsed: unknown = JSON.parse(value);
    return typeof parsed === "object" && parsed !== null
      ? (parsed as Record<string, unknown>)
      : {};
  } catch {
    return {};
  }
}

function readString(data: Record<string, unknown>, key: string): string {
  const value = data[key];
  return typeof value === "string" ? value : "";
}
