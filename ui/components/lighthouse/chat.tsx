"use client";

import { useChat } from "@ai-sdk/react";
import { DefaultChatTransport } from "ai";
import { ChevronDown, Copy, Plus, RotateCcw } from "lucide-react";
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { Streamdown } from "streamdown";

import { getLighthouseModelIds } from "@/actions/lighthouse/lighthouse";
import { Action, Actions } from "@/components/lighthouse/ai-elements/actions";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuTrigger,
} from "@/components/lighthouse/ai-elements/dropdown-menu";
import {
  PromptInput,
  PromptInputBody,
  PromptInputSubmit,
  PromptInputTextarea,
  PromptInputToolbar,
  PromptInputTools,
} from "@/components/lighthouse/ai-elements/prompt-input";
import { Loader } from "@/components/lighthouse/loader";
import { useToast } from "@/components/ui";
import { CustomButton } from "@/components/ui/custom";
import { CustomLink } from "@/components/ui/custom/custom-link";
import { cn } from "@/lib/utils";
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
    isDropdownOpen: boolean;
    modelSearchTerm: string;
    hoveredProvider: LighthouseProvider | "";
  }>({
    inputValue: "",
    isDropdownOpen: false,
    modelSearchTerm: "",
    hoveredProvider: defaultProviderId || initialProviders[0]?.id || "",
  });

  // Error handling
  const [errorMessage, setErrorMessage] = useState<string | null>(null);

  // Provider and model management
  const [providers, setProviders] = useState<Provider[]>(initialProviders);
  const [providerLoadState, setProviderLoadState] = useState<{
    loaded: Set<LighthouseProvider>;
    loading: Set<LighthouseProvider>;
  }>({
    loaded: new Set(),
    loading: new Set(),
  });

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

  // Load all models for a specific provider
  const loadModelsForProvider = useCallback(
    async (providerType: LighthouseProvider) => {
      setProviderLoadState((prev) => {
        // Skip if already loaded or currently loading
        if (prev.loaded.has(providerType) || prev.loading.has(providerType)) {
          return prev;
        }

        // Mark as loading
        return {
          ...prev,
          loading: new Set([...Array.from(prev.loading), providerType]),
        };
      });

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

          // Mark as loaded and remove from loading
          setProviderLoadState((prev) => ({
            loaded: new Set([...Array.from(prev.loaded), providerType]),
            loading: new Set(
              Array.from(prev.loading).filter((id) => id !== providerType),
            ),
          }));
        }
      } catch (error) {
        console.error(`Error loading models for ${providerType}:`, error);
        // Remove from loading state on error
        setProviderLoadState((prev) => ({
          ...prev,
          loading: new Set(
            Array.from(prev.loading).filter((id) => id !== providerType),
          ),
        }));
      }
    },
    [],
  );

  const { messages, sendMessage, status, error, setMessages, regenerate } =
    useChat({
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
        const firstTextPart = message.parts.find((p) => p.type === "text");
        if (
          firstTextPart &&
          "text" in firstTextPart &&
          firstTextPart.text.startsWith("[LIGHTHOUSE_ANALYST_ERROR]:")
        ) {
          const errorText = firstTextPart.text
            .replace("[LIGHTHOUSE_ANALYST_ERROR]:", "")
            .trim();
          setErrorMessage(errorText);
          // Remove error message from chat history
          setMessages((prev) =>
            prev.filter((m) => {
              const textPart = m.parts.find((p) => p.type === "text");
              return !(
                textPart &&
                "text" in textPart &&
                textPart.text.startsWith("[LIGHTHOUSE_ANALYST_ERROR]:")
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

  const messagesContainerRef = useRef<HTMLDivElement | null>(null);

  const restoreLastUserMessage = useCallback(() => {
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
  }, [setMessages]);

  // Auto-scroll to bottom when new messages arrive or when streaming
  useEffect(() => {
    if (messagesContainerRef.current) {
      messagesContainerRef.current.scrollTop =
        messagesContainerRef.current.scrollHeight;
    }
  }, [messages, status]);

  // Handle dropdown state changes
  useEffect(() => {
    if (uiState.isDropdownOpen && uiState.hoveredProvider) {
      loadModelsForProvider(uiState.hoveredProvider as LighthouseProvider);
    }
  }, [uiState.isDropdownOpen, uiState.hoveredProvider, loadModelsForProvider]);

  // Memoize filtered models to avoid recalculation on every render
  const filteredModels = useMemo(() => {
    const currentProvider = providers.find(
      (p) => p.id === uiState.hoveredProvider,
    );
    return (
      currentProvider?.models.filter((model) =>
        model.name
          .toLowerCase()
          .includes(uiState.modelSearchTerm.toLowerCase()),
      ) || []
    );
  }, [providers, uiState.hoveredProvider, uiState.modelSearchTerm]);

  // Handlers
  const handleNewChat = useCallback(() => {
    setMessages([]);
    setErrorMessage(null);
    setUiState((prev) => ({ ...prev, inputValue: "" }));
  }, [setMessages]);

  const handleModelSelect = useCallback(
    (providerType: LighthouseProvider, modelId: string, modelName: string) => {
      setSelectedModel({ providerType, modelId, modelName });
      setUiState((prev) => ({
        ...prev,
        isDropdownOpen: false,
        modelSearchTerm: "", // Reset search when selecting
      }));
    },
    [],
  );

  return (
    <div className="bg-background relative flex h-[calc(100vh-(--spacing(16)))] min-w-0 flex-col">
      {/* Header with New Chat button */}
      {messages.length > 0 && (
        <div className="border-default-200 dark:border-default-100 border-b px-4 py-3">
          <div className="flex items-center justify-end">
            <CustomButton
              ariaLabel="Start new chat"
              variant="bordered"
              size="sm"
              startContent={<Plus className="h-4 w-4" />}
              onPress={handleNewChat}
              className="gap-1"
            >
              New Chat
            </CustomButton>
          </div>
        </div>
      )}

      {!hasConfig && (
        <div className="bg-background/80 absolute inset-0 z-50 flex items-center justify-center backdrop-blur-sm">
          <div className="bg-card max-w-md rounded-lg p-6 text-center shadow-lg">
            <h3 className="mb-2 text-lg font-semibold">
              LLM Provider Configuration Required
            </h3>
            <p className="text-muted-foreground mb-4">
              Please configure an LLM provider to use Lighthouse AI.
            </p>
            <CustomLink
              href="/lighthouse/config"
              className="bg-primary text-primary-foreground hover:bg-primary/90 inline-flex items-center justify-center rounded-md px-4 py-2"
              target="_self"
              size="sm"
            >
              Configure Provider
            </CustomLink>
          </div>
        </div>
      )}

      {/* Error Banner */}
      {(error || errorMessage) && (
        <div className="mx-4 mt-4 rounded-lg border border-red-200 bg-red-50 p-4 dark:border-red-800 dark:bg-red-900/20">
          <div className="flex items-start">
            <div className="shrink-0">
              <svg
                className="h-5 w-5 text-red-400"
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
              <h3 className="text-sm font-medium text-red-800 dark:text-red-200">
                Error
              </h3>
              <p className="mt-1 text-sm text-red-700 dark:text-red-300">
                {errorMessage ||
                  error?.message ||
                  "An error occurred. Please retry your message."}
              </p>
              {/* Original error details for native errors */}
              {error && (error as any).status && (
                <p className="mt-1 text-xs text-red-600 dark:text-red-400">
                  Status: {(error as any).status}
                </p>
              )}
              {error && (error as any).body && (
                <details className="mt-2">
                  <summary className="cursor-pointer text-xs text-red-600 hover:text-red-800 dark:text-red-400 dark:hover:text-red-300">
                    Show details
                  </summary>
                  <pre className="mt-1 max-h-20 overflow-auto rounded bg-red-100 p-2 text-xs text-red-800 dark:bg-red-900/30 dark:text-red-200">
                    {JSON.stringify((error as any).body, null, 2)}
                  </pre>
                </details>
              )}
            </div>
          </div>
        </div>
      )}

      {messages.length === 0 && !errorMessage && !error ? (
        <div className="flex flex-1 items-center justify-center p-4">
          <div className="w-full max-w-2xl">
            <h2 className="mb-4 text-center font-sans text-xl">Suggestions</h2>
            <div className="grid gap-2 sm:grid-cols-2">
              {SUGGESTED_ACTIONS.map((action, index) => (
                <CustomButton
                  key={`suggested-action-${index}`}
                  ariaLabel={`Send message: ${action.action}`}
                  onPress={() => {
                    sendMessage({
                      text: action.action,
                    });
                  }}
                  className="hover:bg-muted flex h-auto w-full flex-col items-start justify-start rounded-xl border bg-gray-50 px-4 py-3.5 text-left font-sans text-sm dark:bg-gray-900"
                >
                  <span>{action.title}</span>
                  <span className="text-muted-foreground">{action.label}</span>
                </CustomButton>
              ))}
            </div>
          </div>
        </div>
      ) : (
        <div
          className="no-scrollbar flex flex-1 flex-col gap-4 overflow-y-auto p-4"
          ref={messagesContainerRef}
        >
          {messages.map((message, idx) => {
            const isLastMessage = idx === messages.length - 1;
            const messageText = message.parts
              .filter((p) => p.type === "text")
              .map((p) => ("text" in p ? p.text : ""))
              .join("");

            // Check if this is the streaming assistant message (last message, assistant role, while streaming)
            const isStreamingAssistant =
              isLastMessage &&
              message.role === "assistant" &&
              status === "streaming";

            // Use a composite key to ensure uniqueness even if IDs are duplicated temporarily
            const uniqueKey = `${message.id}-${idx}-${message.role}`;

            return (
              <div key={uniqueKey}>
                <div
                  className={`flex ${
                    message.role === "user" ? "justify-end" : "justify-start"
                  }`}
                >
                  <div
                    className={`max-w-[80%] rounded-lg px-4 py-2 ${
                      message.role === "user"
                        ? "bg-primary text-primary-foreground dark:text-black!"
                        : "bg-muted"
                    }`}
                  >
                    {/* Show loader before text appears or while streaming empty content */}
                    {isStreamingAssistant && !messageText ? (
                      <Loader size="default" text="Thinking..." />
                    ) : (
                      <div
                        className={
                          message.role === "user" ? "dark:text-black!" : ""
                        }
                      >
                        <Streamdown
                          parseIncompleteMarkdown={true}
                          shikiTheme={["github-light", "github-dark"]}
                          controls={{
                            code: true,
                            table: true,
                            mermaid: true,
                          }}
                          allowedLinkPrefixes={["*"]}
                          allowedImagePrefixes={["*"]}
                        >
                          {messageText}
                        </Streamdown>
                      </div>
                    )}
                  </div>
                </div>

                {/* Actions for assistant messages */}
                {message.role === "assistant" &&
                  isLastMessage &&
                  messageText &&
                  status !== "streaming" && (
                    <div className="mt-2 flex justify-start">
                      <Actions className="max-w-[80%]">
                        <Action
                          tooltip="Copy message"
                          label="Copy"
                          onClick={() => {
                            navigator.clipboard.writeText(messageText);
                            toast({
                              title: "Copied",
                              description: "Message copied to clipboard",
                            });
                          }}
                        >
                          <Copy className="h-3 w-3" />
                        </Action>
                        <Action
                          tooltip="Regenerate response"
                          label="Retry"
                          onClick={() => regenerate()}
                        >
                          <RotateCcw className="h-3 w-3" />
                        </Action>
                      </Actions>
                    </div>
                  )}
              </div>
            );
          })}
          {/* Show loader only if no assistant message exists yet */}
          {(status === "submitted" || status === "streaming") &&
            messages.length > 0 &&
            messages[messages.length - 1].role === "user" && (
              <div className="flex justify-start">
                <div className="bg-muted max-w-[80%] rounded-lg px-4 py-2">
                  <Loader size="default" text="Thinking..." />
                </div>
              </div>
            )}
        </div>
      )}

      <div className="mx-auto w-full px-4 pb-16 md:max-w-3xl md:pb-16">
        <PromptInput
          onSubmit={(message) => {
            if (status === "streaming" || status === "submitted") {
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
              {/* Model Selector */}
              <DropdownMenu
                open={uiState.isDropdownOpen}
                onOpenChange={(open) =>
                  setUiState((prev) => ({ ...prev, isDropdownOpen: open }))
                }
              >
                <DropdownMenuTrigger asChild>
                  <button
                    type="button"
                    className="hover:bg-accent text-muted-foreground hover:text-foreground flex items-center gap-1.5 rounded-md px-2.5 py-1.5 text-sm font-medium transition-colors"
                  >
                    <span>{selectedModel.modelName}</span>
                    <ChevronDown className="h-4 w-4" />
                  </button>
                </DropdownMenuTrigger>
                <DropdownMenuContent
                  align="start"
                  className="bg-background w-[400px] border p-0 shadow-lg"
                >
                  <div className="flex h-[300px]">
                    {/* Left column - Providers */}
                    <div className="border-default-200 dark:border-default-100 bg-muted/30 w-[180px] overflow-y-auto border-r p-1">
                      {providers.map((provider) => (
                        <div
                          key={provider.id}
                          onMouseEnter={() => {
                            setUiState((prev) => ({
                              ...prev,
                              hoveredProvider: provider.id,
                              modelSearchTerm: "", // Reset search when changing provider
                            }));
                            loadModelsForProvider(provider.id);
                          }}
                          className={cn(
                            "flex cursor-default items-center justify-between rounded-sm px-3 py-2 text-sm transition-colors",
                            uiState.hoveredProvider === provider.id
                              ? "bg-gray-100 dark:bg-gray-800"
                              : "hover:ring-default-200 dark:hover:ring-default-700 hover:bg-gray-100 hover:ring-1 dark:hover:bg-gray-800",
                          )}
                        >
                          <span className="font-medium">{provider.name}</span>
                          <ChevronDown className="h-4 w-4 -rotate-90" />
                        </div>
                      ))}
                    </div>

                    {/* Right column - Models */}
                    <div className="flex flex-1 flex-col">
                      {/* Search bar */}
                      <div className="border-default-200 dark:border-default-100 border-b p-2">
                        <input
                          type="text"
                          placeholder="Search models..."
                          value={uiState.modelSearchTerm}
                          onChange={(e) =>
                            setUiState((prev) => ({
                              ...prev,
                              modelSearchTerm: e.target.value,
                            }))
                          }
                          className="placeholder:text-muted-foreground w-full rounded-md border border-gray-200 bg-transparent px-3 py-1.5 text-sm outline-hidden focus:border-gray-400 dark:border-gray-700 dark:focus:border-gray-500"
                        />
                      </div>

                      {/* Models list */}
                      <div className="flex-1 overflow-y-auto p-1">
                        {uiState.hoveredProvider &&
                        providerLoadState.loading.has(
                          uiState.hoveredProvider as LighthouseProvider,
                        ) ? (
                          <div className="flex items-center justify-center py-8">
                            <Loader size="sm" text="Loading models..." />
                          </div>
                        ) : filteredModels.length === 0 ? (
                          <div className="text-muted-foreground flex items-center justify-center py-8 text-sm">
                            {uiState.modelSearchTerm
                              ? "No models found"
                              : "No models available"}
                          </div>
                        ) : (
                          filteredModels.map((model) => (
                            <button
                              key={model.id}
                              type="button"
                              onClick={() =>
                                uiState.hoveredProvider &&
                                handleModelSelect(
                                  uiState.hoveredProvider as LighthouseProvider,
                                  model.id,
                                  model.name,
                                )
                              }
                              className={cn(
                                "focus:bg-accent focus:text-accent-foreground hover:ring-default-200 dark:hover:ring-default-700 relative flex w-full cursor-default items-center rounded-sm px-3 py-2 text-left text-sm outline-hidden transition-colors hover:bg-gray-100 hover:ring-1 dark:hover:bg-gray-800",
                                selectedModel.modelId === model.id &&
                                  selectedModel.providerType ===
                                    uiState.hoveredProvider
                                  ? "bg-accent text-accent-foreground"
                                  : "",
                              )}
                            >
                              {model.name}
                            </button>
                          ))
                        )}
                      </div>
                    </div>
                  </div>
                </DropdownMenuContent>
              </DropdownMenu>
            </PromptInputTools>

            {/* Submit Button */}
            <PromptInputSubmit
              status={status}
              disabled={
                status === "streaming" ||
                status === "submitted" ||
                !uiState.inputValue?.trim()
              }
            />
          </PromptInputToolbar>
        </PromptInput>
      </div>
    </div>
  );
};

export default Chat;
