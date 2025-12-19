"use client";

import { useChat } from "@ai-sdk/react";
import { DefaultChatTransport } from "ai";
import { Plus } from "lucide-react";
import { useEffect, useRef, useState } from "react";

import { getLighthouseModelIds } from "@/actions/lighthouse/lighthouse";
import {
  Conversation,
  ConversationContent,
  ConversationScrollButton,
} from "@/components/ai-elements/conversation";
import {
  PromptInput,
  PromptInputBody,
  PromptInputSubmit,
  PromptInputTextarea,
  PromptInputToolbar,
  PromptInputTools,
} from "@/components/lighthouse/ai-elements/prompt-input";
import {
  ERROR_PREFIX,
  MESSAGE_ROLES,
  MESSAGE_STATUS,
} from "@/components/lighthouse/chat-utils";
import { Loader } from "@/components/lighthouse/loader";
import { MessageItem } from "@/components/lighthouse/message-item";
import {
  Button,
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
  Combobox,
} from "@/components/shadcn";
import { useToast } from "@/components/ui";
import { CustomLink } from "@/components/ui/custom/custom-link";
import type { LighthouseProvider } from "@/types/lighthouse";

interface Model {
  id: string;
  name: string;
}

interface Provider {
  id: LighthouseProvider;
  name: string;
  models: Model[];
}

interface SuggestedAction {
  title: string;
  label: string;
  action: string;
}

interface ChatProps {
  hasConfig: boolean;
  providers: Provider[];
  defaultProviderId?: LighthouseProvider;
  defaultModelId?: string;
}

interface SelectedModel {
  providerType: LighthouseProvider | "";
  modelId: string;
  modelName: string;
}

interface ExtendedError extends Error {
  status?: number;
  body?: Record<string, unknown>;
}

const SUGGESTED_ACTIONS: SuggestedAction[] = [
  {
    title: "Are there any exposed S3",
    label: "buckets in my AWS accounts?",
    action: "List exposed S3 buckets in my AWS accounts",
  },
  {
    title: "What is the risk of having",
    label: "RDS databases unencrypted?",
    action: "What is the risk of having RDS databases unencrypted?",
  },
  {
    title: "What is the CIS 1.10 compliance status",
    label: "of my Kubernetes cluster?",
    action: "What is the CIS 1.10 compliance status of my Kubernetes cluster?",
  },
  {
    title: "List my highest privileged",
    label: "AWS IAM users with full admin access?",
    action: "List my highest privileged AWS IAM users with full admin access",
  },
];

export const Chat = ({
  hasConfig,
  providers: initialProviders,
  defaultProviderId,
  defaultModelId,
}: ChatProps) => {
  const { toast } = useToast();

  // Consolidated UI state
  const [uiState, setUiState] = useState<{
    inputValue: string;
  }>({
    inputValue: "",
  });

  // Error handling
  const [errorMessage, setErrorMessage] = useState<string | null>(null);

  // Provider and model management
  const [providers, setProviders] = useState<Provider[]>(initialProviders);
  const loadedProvidersRef = useRef<Set<LighthouseProvider>>(new Set());
  const [loadingProviders, setLoadingProviders] = useState<
    Set<LighthouseProvider>
  >(new Set());

  // Initialize selectedModel with defaults from props
  const [selectedModel, setSelectedModel] = useState<SelectedModel>(() => {
    const defaultProvider =
      initialProviders.find((p) => p.id === defaultProviderId) ||
      initialProviders[0];
    const defaultModel =
      defaultProvider?.models.find((m) => m.id === defaultModelId) ||
      defaultProvider?.models[0];

    return {
      providerType: defaultProvider?.id || "",
      modelId: defaultModel?.id || "",
      modelName: defaultModel?.name || "",
    };
  });

  // Keep ref in sync with selectedModel for stable access in callbacks
  const selectedModelRef = useRef(selectedModel);
  selectedModelRef.current = selectedModel;

  // Load models for all providers on mount
  useEffect(() => {
    initialProviders.forEach((provider) => {
      loadModelsForProvider(provider.id);
    });
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // Load all models for a specific provider
  const loadModelsForProvider = async (providerType: LighthouseProvider) => {
    // Skip if already loaded
    if (loadedProvidersRef.current.has(providerType)) {
      return;
    }

    // Mark as loaded
    loadedProvidersRef.current.add(providerType);
    setLoadingProviders((prev) => new Set(prev).add(providerType));

    try {
      const response = await getLighthouseModelIds(providerType);

      if (response.errors) {
        console.error(
          `Error loading models for ${providerType}:`,
          response.errors,
        );
        return;
      }

      if (response.data && Array.isArray(response.data)) {
        // Use the model data directly from the API
        const models: Model[] = response.data;

        // Update the provider's models
        setProviders((prev) =>
          prev.map((p) => (p.id === providerType ? { ...p, models } : p)),
        );
      }
    } catch (error) {
      console.error(`Error loading models for ${providerType}:`, error);
      // Remove from loaded on error so it can be retried
      loadedProvidersRef.current.delete(providerType);
    } finally {
      setLoadingProviders((prev) => {
        const next = new Set(prev);
        next.delete(providerType);
        return next;
      });
    }
  };

  const {
    messages,
    sendMessage,
    status,
    error,
    setMessages,
    regenerate,
    stop,
  } = useChat({
    transport: new DefaultChatTransport({
      api: "/api/lighthouse/analyst",
      credentials: "same-origin",
      body: () => ({
        model: selectedModelRef.current.modelId,
        provider: selectedModelRef.current.providerType,
      }),
    }),
    experimental_throttle: 100,
    onFinish: ({ message }) => {
      // There is no specific way to output the error message from langgraph supervisor
      // Hence, all error messages are sent as normal messages with the prefix [LIGHTHOUSE_ANALYST_ERROR]:
      // Detect error messages sent from backend using specific prefix and display the error
      // Use includes() instead of startsWith() to catch errors that occur mid-stream (after text has been sent)
      const firstTextPart = message.parts.find((p) => p.type === "text");
      if (
        firstTextPart &&
        "text" in firstTextPart &&
        firstTextPart.text.includes(ERROR_PREFIX)
      ) {
        // Extract error text - handle both start-of-message and mid-stream errors
        const fullText = firstTextPart.text;
        const errorIndex = fullText.indexOf(ERROR_PREFIX);
        const errorText = fullText
          .substring(errorIndex + ERROR_PREFIX.length)
          .trim();
        setErrorMessage(errorText);
        // Remove error message from chat history
        setMessages((prev) =>
          prev.filter((m) => {
            const textPart = m.parts.find((p) => p.type === "text");
            return !(
              textPart &&
              "text" in textPart &&
              textPart.text.includes(ERROR_PREFIX)
            );
          }),
        );
        restoreLastUserMessage();
      }
    },
    onError: (error) => {
      console.error("Chat error:", error);

      if (
        error?.message?.includes("<html>") &&
        error?.message?.includes("<title>403 Forbidden</title>")
      ) {
        restoreLastUserMessage();
        setErrorMessage("403 Forbidden");
        return;
      }

      restoreLastUserMessage();
      setErrorMessage(
        error?.message || "An error occurred. Please retry your message.",
      );
    },
  });

  const restoreLastUserMessage = () => {
    let restoredText = "";

    setMessages((currentMessages) => {
      const nextMessages = [...currentMessages];

      for (let index = nextMessages.length - 1; index >= 0; index -= 1) {
        const current = nextMessages[index];

        if (current.role !== "user") {
          continue;
        }

        const textPart = current.parts.find(
          (part): part is { type: "text"; text: string } =>
            part.type === "text" && "text" in part,
        );

        if (textPart) {
          restoredText = textPart.text;
        }

        nextMessages.splice(index, 1);
        break;
      }

      return nextMessages;
    });

    if (restoredText) {
      setUiState((prev) => ({ ...prev, inputValue: restoredText }));
    }
  };

  const stopGeneration = () => {
    if (
      status === MESSAGE_STATUS.STREAMING ||
      status === MESSAGE_STATUS.SUBMITTED
    ) {
      stop();
    }
  };

  // Handlers
  const handleNewChat = () => {
    setMessages([]);
    setErrorMessage(null);
    setUiState((prev) => ({ ...prev, inputValue: "" }));
  };

  const handleModelSelect = (
    providerType: LighthouseProvider,
    modelId: string,
    modelName: string,
  ) => {
    setSelectedModel({ providerType, modelId, modelName });
  };

  return (
    <div className="relative flex h-full min-w-0 flex-col overflow-hidden">
      {/* Header with New Chat button */}
      {messages.length > 0 && (
        <div className="border-default-200 dark:border-default-100 border-b px-2 py-3 sm:px-4">
          <div className="flex items-center justify-end">
            <Button
              aria-label="Start new chat"
              variant="outline"
              size="sm"
              onClick={handleNewChat}
              className="gap-1"
            >
              <Plus className="h-4 w-4" />
              New Chat
            </Button>
          </div>
        </div>
      )}

      {!hasConfig && (
        <div className="bg-background/80 absolute inset-0 z-50 flex items-center justify-center backdrop-blur-sm">
          <Card
            variant="base"
            padding="lg"
            className="max-w-md text-center shadow-lg"
          >
            <CardHeader>
              <CardTitle>LLM Provider Configuration Required</CardTitle>
              <CardDescription>
                Please configure an LLM provider to use Lighthouse AI.
              </CardDescription>
            </CardHeader>
            <CardContent>
              <CustomLink
                href="/lighthouse/config"
                className="bg-primary text-primary-foreground hover:bg-primary/90 inline-flex items-center justify-center rounded-md px-4 py-2"
                target="_self"
                size="sm"
              >
                Configure Provider
              </CustomLink>
            </CardContent>
          </Card>
        </div>
      )}

      {/* Error Banner */}
      {(error || errorMessage) && (
        <div className="border-border-error-primary bg-bg-fail-secondary mx-2 mt-4 rounded-lg border p-4 sm:mx-4">
          <div className="flex items-start">
            <div className="shrink-0">
              <svg
                className="text-text-error h-5 w-5"
                viewBox="0 0 20 20"
                fill="currentColor"
              >
                <path
                  fillRule="evenodd"
                  d="M10 18a8 8 0 100-16 8 8 0 000 16zM8.28 7.22a.75.75 0 00-1.06 1.06L8.94 10l-1.72 1.72a.75.75 0 101.06 1.06L10 11.06l1.72 1.72a.75.75 0 101.06-1.06L11.06 10l1.72-1.72a.75.75 0 00-1.06-1.06L10 8.94 8.28 7.22z"
                  clipRule="evenodd"
                />
              </svg>
            </div>
            <div className="ml-3">
              <h3 className="text-text-error text-sm font-medium">Error</h3>
              <p className="text-text-neutral-secondary mt-1 text-sm">
                {errorMessage ||
                  error?.message ||
                  "An error occurred. Please retry your message."}
              </p>
              {/* Original error details for native errors */}
              {error && (error as ExtendedError).status && (
                <p className="text-text-neutral-tertiary mt-1 text-xs">
                  Status: {(error as ExtendedError).status}
                </p>
              )}
              {error && (error as ExtendedError).body && (
                <details className="mt-2">
                  <summary className="text-text-neutral-tertiary hover:text-text-neutral-secondary cursor-pointer text-xs">
                    Show details
                  </summary>
                  <pre className="bg-bg-neutral-tertiary text-text-neutral-secondary mt-1 max-h-20 overflow-auto rounded p-2 text-xs">
                    {JSON.stringify((error as ExtendedError).body, null, 2)}
                  </pre>
                </details>
              )}
            </div>
          </div>
        </div>
      )}

      {messages.length === 0 && !errorMessage && !error ? (
        <div className="flex flex-1 items-center justify-center px-2 py-4 sm:p-4">
          <div className="w-full max-w-2xl">
            <h2 className="mb-4 text-center font-sans text-xl">Suggestions</h2>
            <div className="grid gap-2 sm:grid-cols-2">
              {SUGGESTED_ACTIONS.map((action, index) => (
                <Button
                  key={`suggested-action-${index}`}
                  aria-label={`Send message: ${action.action}`}
                  onClick={() => {
                    sendMessage({
                      text: action.action,
                    });
                  }}
                  variant="outline"
                  className="flex h-auto w-full flex-col items-start justify-start rounded-xl px-4 py-3.5 text-left font-sans text-sm"
                >
                  <span>{action.title}</span>
                  <span className="text-muted-foreground">{action.label}</span>
                </Button>
              ))}
            </div>
          </div>
        </div>
      ) : (
        <Conversation className="flex-1">
          <ConversationContent className="gap-4 px-2 py-4 sm:p-4">
            {messages.map((message, idx) => (
              <MessageItem
                key={`${message.id}-${idx}-${message.role}`}
                message={message}
                index={idx}
                isLastMessage={idx === messages.length - 1}
                status={status}
                onCopy={(text) => {
                  navigator.clipboard.writeText(text);
                  toast({
                    title: "Copied",
                    description: "Message copied to clipboard",
                  });
                }}
                onRegenerate={regenerate}
              />
            ))}
            {/* Show loader only if no assistant message exists yet */}
            {(status === MESSAGE_STATUS.SUBMITTED ||
              status === MESSAGE_STATUS.STREAMING) &&
              messages.length > 0 &&
              messages[messages.length - 1].role === MESSAGE_ROLES.USER && (
                <div className="flex justify-start">
                  <div className="bg-muted max-w-[80%] rounded-lg px-4 py-2">
                    <Loader size="default" text="Thinking..." />
                  </div>
                </div>
              )}
          </ConversationContent>
          <ConversationScrollButton />
        </Conversation>
      )}

      <div className="mx-auto w-full px-4 pb-16 md:max-w-3xl md:pb-16">
        <PromptInput
          onSubmit={(message) => {
            if (
              status === MESSAGE_STATUS.STREAMING ||
              status === MESSAGE_STATUS.SUBMITTED
            ) {
              return;
            }
            if (message.text?.trim()) {
              setErrorMessage(null);
              sendMessage({
                text: message.text,
              });
              setUiState((prev) => ({ ...prev, inputValue: "" }));
            }
          }}
        >
          <PromptInputBody>
            <PromptInputTextarea
              placeholder={
                error || errorMessage
                  ? "Edit your message and try again..."
                  : "Type your message..."
              }
              value={uiState.inputValue}
              onChange={(e) =>
                setUiState((prev) => ({ ...prev, inputValue: e.target.value }))
              }
            />
          </PromptInputBody>

          <PromptInputToolbar>
            <PromptInputTools>
              {/* Model Selector - Combobox */}
              <Combobox
                value={`${selectedModel.providerType}:${selectedModel.modelId}`}
                onValueChange={(value) => {
                  const separatorIndex = value.indexOf(":");
                  if (separatorIndex === -1) return;

                  const providerType = value.slice(
                    0,
                    separatorIndex,
                  ) as LighthouseProvider;
                  const modelId = value.slice(separatorIndex + 1);
                  const provider = providers.find((p) => p.id === providerType);
                  const model = provider?.models.find((m) => m.id === modelId);
                  if (provider && model) {
                    handleModelSelect(providerType, modelId, model.name);
                  }
                }}
                groups={providers.map((provider) => ({
                  heading: provider.name,
                  options: provider.models.map((model) => ({
                    value: `${provider.id}:${model.id}`,
                    label: model.name,
                  })),
                }))}
                loading={loadingProviders.size > 0}
                loadingMessage="Loading models..."
                placeholder={selectedModel.modelName || "Select model..."}
                searchPlaceholder="Search models..."
                emptyMessage="No model found."
                showSelectedFirst={true}
              />
            </PromptInputTools>

            {/* Submit Button */}
            <PromptInputSubmit
              status={status}
              type={
                status === MESSAGE_STATUS.STREAMING ||
                status === MESSAGE_STATUS.SUBMITTED
                  ? "button"
                  : "submit"
              }
              onClick={(event) => {
                if (
                  status === MESSAGE_STATUS.STREAMING ||
                  status === MESSAGE_STATUS.SUBMITTED
                ) {
                  event.preventDefault();
                  stopGeneration();
                }
              }}
              disabled={
                !uiState.inputValue?.trim() &&
                status !== MESSAGE_STATUS.STREAMING &&
                status !== MESSAGE_STATUS.SUBMITTED
              }
            />
          </PromptInputToolbar>
        </PromptInput>
      </div>
    </div>
  );
};

export default Chat;
