"use client";

import {
  ArrowRight,
  BookOpen,
  Bot,
  FileCheck2,
  Loader2,
  Network,
  Settings,
  ShieldAlert,
  Square,
  UserRound,
} from "lucide-react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { type FormEvent, useRef, useState } from "react";

import {
  cancelLighthouseV2Run,
  createLighthouseV2Session,
  getLighthouseV2Messages,
  sendLighthouseV2Message,
} from "@/actions/lighthouse-v2/lighthouse-v2";
import {
  Conversation,
  ConversationContent,
  ConversationScrollButton,
} from "@/components/ai-elements/conversation";
import { LighthouseIcon } from "@/components/icons/Icons";
import { Button } from "@/components/shadcn/button/button";
import { Textarea } from "@/components/shadcn/textarea/textarea";
import { useMountEffect } from "@/hooks/use-mount-effect";
import {
  createInitialLighthouseV2StreamState,
  type LighthouseV2StreamState,
  reduceLighthouseV2Event,
} from "@/lib/lighthouse-v2/event-reducer";
import { notifyLighthouseV2SessionsChanged } from "@/lib/lighthouse-v2/session-events";
import { cn } from "@/lib/utils";
import {
  LIGHTHOUSE_V2_MESSAGE_ROLE,
  LIGHTHOUSE_V2_PART_TYPE,
  LIGHTHOUSE_V2_PROVIDER_TYPE,
  LIGHTHOUSE_V2_SSE_EVENT,
  type LighthouseV2Configuration,
  type LighthouseV2Message,
  type LighthouseV2ProviderType,
  type LighthouseV2SSEEvent,
  type LighthouseV2SupportedModel,
} from "@/types/lighthouse-v2";

interface LighthouseV2ChatPageProps {
  configurations: LighthouseV2Configuration[];
  modelsByProvider: Record<
    LighthouseV2ProviderType,
    LighthouseV2SupportedModel[]
  >;
  initialSessionId?: string;
  initialMessages: LighthouseV2Message[];
  initialPrompt?: string;
}

const LIGHTHOUSE_V2_SUGGESTIONS = [
  {
    label: "Critical findings",
    prompt: "Summarize my most critical open findings and what to fix first.",
    icon: ShieldAlert,
  },
  {
    label: "Compliance gaps",
    prompt: "What are my highest-impact compliance gaps right now?",
    icon: FileCheck2,
  },
  {
    label: "Attack paths",
    prompt: "Find risky attack paths and explain the exposure.",
    icon: Network,
  },
  {
    label: "Docs",
    prompt: "Point me to the relevant Prowler documentation for this task.",
    icon: BookOpen,
  },
] as const;

export function LighthouseV2ChatPage({
  configurations,
  modelsByProvider,
  initialSessionId,
  initialMessages,
  initialPrompt,
}: LighthouseV2ChatPageProps) {
  const router = useRouter();
  const eventSourceRef = useRef<EventSource | null>(null);
  const initialPromptSentRef = useRef(false);
  const connectedConfigurations = configurations.filter(
    (configuration) => configuration.connected === true,
  );
  const selectedConfiguration = connectedConfigurations[0] ?? configurations[0];
  const selectedProvider =
    selectedConfiguration?.providerType ?? LIGHTHOUSE_V2_PROVIDER_TYPE.OPENAI;
  const selectedModel =
    selectedConfiguration?.defaultModel ??
    modelsByProvider[selectedProvider]?.[0]?.id ??
    "";
  const [activeSessionId, setActiveSessionId] = useState<string | null>(
    initialSessionId ?? null,
  );
  const [messages, setMessages] = useState(initialMessages);
  const [input, setInput] = useState("");
  const [feedback, setFeedback] = useState<string | null>(null);
  const [blockedByConflict, setBlockedByConflict] = useState(false);
  const [lastSubmittedText, setLastSubmittedText] = useState<string | null>(
    null,
  );
  const [streamState, setStreamState] = useState<LighthouseV2StreamState>(() =>
    createInitialLighthouseV2StreamState(),
  );

  const canSend =
    selectedConfiguration?.connected === true &&
    !streamState.activeTaskId &&
    !blockedByConflict;

  const refreshMessages = async (sessionId: string) => {
    const result = await getLighthouseV2Messages(sessionId);
    if ("data" in result) {
      setMessages(result.data);
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
    notifyLighthouseV2SessionsChanged();
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
    notifyLighthouseV2SessionsChanged();
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
    notifyLighthouseV2SessionsChanged();
    if ("error" in result) {
      setFeedback(result.error);
    }
  };

  useMountEffect(() => {
    return () => closeStream();
  });

  useMountEffect(() => {
    if (initialPrompt && !initialPromptSentRef.current) {
      initialPromptSentRef.current = true;
      void submitMessage(initialPrompt);
    }
  });

  const hasConversation =
    messages.length > 0 || Boolean(streamState.assistantText);

  return (
    <section className="bg-bg-neutral-primary flex h-full min-h-0 flex-col">
      {hasConversation ? (
        <div className="flex min-h-0 flex-1 flex-col">
          <Conversation className="min-h-0">
            <ConversationContent className="mx-auto w-full max-w-4xl gap-5 px-4 py-8 md:px-8">
              {messages.map((message) => (
                <MessageBubble key={message.id} message={message} />
              ))}
              {streamState.assistantText && (
                <StreamingAssistantMessage streamState={streamState} />
              )}
            </ConversationContent>
            <ConversationScrollButton />
          </Conversation>
          <div className="bg-bg-neutral-primary px-4 pb-5 md:px-8">
            <div className="mx-auto w-full max-w-4xl">
              <LighthouseV2Feedback
                feedback={feedback}
                canRetry={
                  streamState.status === "disconnected" &&
                  lastSubmittedText !== null
                }
                onRetry={() =>
                  lastSubmittedText
                    ? void submitMessage(lastSubmittedText)
                    : undefined
                }
              />
              <LighthouseV2Composer
                canSend={canSend}
                input={input}
                isStreaming={Boolean(streamState.activeTaskId)}
                selectedConfigurationConnected={
                  selectedConfiguration?.connected === true
                }
                onInputChange={setInput}
                onStop={handleStop}
                onSubmit={handleSubmit}
                onSubmitText={submitMessage}
              />
            </div>
          </div>
        </div>
      ) : (
        <div className="flex min-h-0 flex-1 items-center justify-center px-4 py-10 md:px-8">
          <div className="mx-auto flex w-full max-w-5xl flex-col items-center gap-5">
            <LighthouseIcon className="size-12" />
            <div className="space-y-2 text-center">
              <h1 className="text-text-neutral-primary text-3xl font-semibold">
                What do you want to know today?
              </h1>
              <p className="text-text-neutral-secondary text-base italic">
                Understand and secure your cloud.
              </p>
            </div>
            <div className="w-full max-w-4xl">
              <LighthouseV2Feedback
                feedback={feedback}
                canRetry={
                  streamState.status === "disconnected" &&
                  lastSubmittedText !== null
                }
                onRetry={() =>
                  lastSubmittedText
                    ? void submitMessage(lastSubmittedText)
                    : undefined
                }
              />
              <LighthouseV2Composer
                canSend={canSend}
                input={input}
                isStreaming={Boolean(streamState.activeTaskId)}
                selectedConfigurationConnected={
                  selectedConfiguration?.connected === true
                }
                onInputChange={setInput}
                onStop={handleStop}
                onSubmit={handleSubmit}
                onSubmitText={submitMessage}
              />
            </div>
            <div className="flex max-w-4xl flex-wrap items-center justify-center gap-2">
              <span className="text-text-neutral-secondary basis-full text-center text-sm font-medium">
                Try Lighthouse for...
              </span>
              {LIGHTHOUSE_V2_SUGGESTIONS.map((suggestion) => {
                const Icon = suggestion.icon;
                return (
                  <Button
                    key={suggestion.label}
                    type="button"
                    variant="outline"
                    size="sm"
                    onClick={() => setInput(suggestion.prompt)}
                  >
                    <Icon className="size-4" />
                    {suggestion.label}
                  </Button>
                );
              })}
              <Button type="button" variant="outline" size="icon-sm" asChild>
                <Link
                  href="/lighthouse/config"
                  aria-label="Lighthouse settings"
                >
                  <Settings className="size-4" />
                </Link>
              </Button>
            </div>
          </div>
        </div>
      )}
    </section>
  );
}

interface LighthouseV2FeedbackProps {
  feedback: string | null;
  canRetry: boolean;
  onRetry: () => void;
}

function LighthouseV2Feedback({
  feedback,
  canRetry,
  onRetry,
}: LighthouseV2FeedbackProps) {
  if (!feedback) return null;

  return (
    <div className="border-border-neutral-secondary bg-bg-neutral-secondary mb-3 flex items-center justify-between gap-3 rounded-[8px] border px-3 py-2 text-sm">
      <span>{feedback}</span>
      {canRetry && (
        <Button type="button" variant="outline" size="sm" onClick={onRetry}>
          Retry
        </Button>
      )}
    </div>
  );
}

interface LighthouseV2ComposerProps {
  canSend: boolean;
  input: string;
  isStreaming: boolean;
  selectedConfigurationConnected: boolean;
  onInputChange: (value: string) => void;
  onStop: () => void;
  onSubmit: (event: FormEvent<HTMLFormElement>) => void;
  onSubmitText: (text: string) => Promise<void>;
}

function LighthouseV2Composer({
  canSend,
  input,
  isStreaming,
  selectedConfigurationConnected,
  onInputChange,
  onStop,
  onSubmit,
  onSubmitText,
}: LighthouseV2ComposerProps) {
  return (
    <form
      className="border-border-neutral-secondary bg-bg-neutral-secondary flex min-h-[150px] w-full flex-col rounded-[8px] border shadow-xs"
      onSubmit={onSubmit}
    >
      <Textarea
        aria-label="Message"
        value={input}
        onChange={(event) => onInputChange(event.target.value)}
        disabled={!canSend}
        placeholder={
          selectedConfigurationConnected
            ? "Ask a question"
            : "Connect a provider first"
        }
        variant="ghost"
        textareaSize="lg"
        className="min-h-[104px] flex-1 rounded-b-none border-0 hover:bg-transparent focus:bg-transparent focus:ring-0"
        onKeyDown={(event) => {
          if (event.key === "Enter" && !event.shiftKey) {
            event.preventDefault();
            void onSubmitText(input);
          }
        }}
      />
      <div className="flex items-center justify-end px-3 pb-3">
        {isStreaming ? (
          <Button
            type="button"
            variant="outline"
            size="icon-sm"
            onClick={onStop}
          >
            <Square className="size-4" />
          </Button>
        ) : (
          <Button
            type="submit"
            size="icon-sm"
            disabled={!canSend || !input.trim()}
          >
            <ArrowRight className="size-4" />
          </Button>
        )}
      </div>
    </form>
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
