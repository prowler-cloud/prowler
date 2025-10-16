"use client";

import { useChat } from "@ai-sdk/react";
import { DefaultChatTransport } from "ai";
import { Copy, Play, Plus, RotateCcw, Square } from "lucide-react";
import { useEffect, useRef, useState } from "react";
import { useForm } from "react-hook-form";

import { Action, Actions } from "@/components/lighthouse/actions";
import { Loader } from "@/components/lighthouse/loader";
import { MemoizedMarkdown } from "@/components/lighthouse/memoized-markdown";
import { useToast } from "@/components/ui";
import { CustomButton, CustomTextarea } from "@/components/ui/custom";
import { CustomLink } from "@/components/ui/custom/custom-link";
import { Form } from "@/components/ui/form";

interface SuggestedAction {
  title: string;
  label: string;
  action: string;
}

interface ChatProps {
  hasConfig: boolean;
  isActive: boolean;
}

interface ChatFormData {
  message: string;
}

export const Chat = ({ hasConfig, isActive }: ChatProps) => {
  const [errorMessage, setErrorMessage] = useState<string | null>(null);
  const { toast } = useToast();

  const { messages, sendMessage, status, error, setMessages, regenerate } =
    useChat({
      transport: new DefaultChatTransport({
        api: "/api/lighthouse/analyst",
        credentials: "same-origin",
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
        }
      },
      onError: (error) => {
        console.error("Chat error:", error);

        if (
          error?.message?.includes("<html>") &&
          error?.message?.includes("<title>403 Forbidden</title>")
        ) {
          setErrorMessage("403 Forbidden");
          return;
        }

        setErrorMessage(
          error?.message || "An error occurred. Please retry your message.",
        );
      },
    });

  const form = useForm<ChatFormData>({
    defaultValues: {
      message: "",
    },
  });

  const messageValue = form.watch("message");
  const messagesContainerRef = useRef<HTMLDivElement | null>(null);
  const latestUserMsgRef = useRef<HTMLDivElement | null>(null);
  const messageValueRef = useRef<string>("");

  // Keep ref in sync with current value
  messageValueRef.current = messageValue;

  // Restore last user message to input when any error occurs
  useEffect(() => {
    if (errorMessage) {
      // Capture current messages to avoid dependency issues
      setMessages((currentMessages) => {
        const lastUserMessage = currentMessages
          .filter((m) => m.role === "user")
          .pop();

        if (lastUserMessage) {
          const textPart = lastUserMessage.parts.find((p) => p.type === "text");
          if (textPart && "text" in textPart) {
            form.setValue("message", textPart.text);
          }
          // Remove the last user message from history since it's now in the input
          return currentMessages.slice(0, -1);
        }

        return currentMessages;
      });
    }
  }, [errorMessage, form, setMessages]);

  // Reset form when message is sent
  useEffect(() => {
    if (status === "submitted") {
      form.reset({ message: "" });
    }
  }, [status, form]);

  // Auto-scroll to bottom when new messages arrive or when streaming
  useEffect(() => {
    if (messagesContainerRef.current) {
      messagesContainerRef.current.scrollTop =
        messagesContainerRef.current.scrollHeight;
    }
  }, [messages, status]);

  const onFormSubmit = form.handleSubmit((data) => {
    // Block submission while streaming or submitted
    if (status === "streaming" || status === "submitted") {
      return;
    }

    if (data.message.trim()) {
      // Clear error on new submission
      setErrorMessage(null);
      sendMessage({ text: data.message });
      form.reset();
    }
  });

  // Global keyboard shortcut handler
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === "Enter" && !e.shiftKey) {
        e.preventDefault();
        // Block enter key while streaming or submitted
        if (
          messageValue?.trim() &&
          status !== "streaming" &&
          status !== "submitted"
        ) {
          onFormSubmit();
        }
      }
    };

    document.addEventListener("keydown", handleKeyDown);
    return () => document.removeEventListener("keydown", handleKeyDown);
  }, [messageValue, onFormSubmit, status]);

  const suggestedActions: SuggestedAction[] = [
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
      action:
        "What is the CIS 1.10 compliance status of my Kubernetes cluster?",
    },
    {
      title: "List my highest privileged",
      label: "AWS IAM users with full admin access?",
      action: "List my highest privileged AWS IAM users with full admin access",
    },
  ];

  // Determine if chat should be disabled
  const shouldDisableChat = !hasConfig || !isActive;

  const handleNewChat = () => {
    setMessages([]);
    setErrorMessage(null);
    form.reset({ message: "" });
  };

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

      {shouldDisableChat && (
        <div className="bg-background/80 absolute inset-0 z-50 flex items-center justify-center backdrop-blur-sm">
          <div className="bg-card max-w-md rounded-lg p-6 text-center shadow-lg">
            <h3 className="mb-2 text-lg font-semibold">
              {!hasConfig
                ? "OpenAI API Key Required"
                : "OpenAI API Key Invalid"}
            </h3>
            <p className="text-muted-foreground mb-4">
              {!hasConfig
                ? "Please configure your OpenAI API key to use Lighthouse AI."
                : "OpenAI API key is invalid. Please update your key to use Lighthouse AI."}
            </p>
            <CustomLink
              href="/lighthouse/config"
              className="bg-primary text-primary-foreground hover:bg-primary/90 inline-flex items-center justify-center rounded-md px-4 py-2"
              target="_self"
              size="sm"
            >
              Configure API Key
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
              {suggestedActions.map((action, index) => (
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
            const lastUserIdx = messages
              .map((m, i) => (m.role === "user" ? i : -1))
              .filter((i) => i !== -1)
              .pop();
            const isLatestUserMsg =
              message.role === "user" && lastUserIdx === idx;
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
                  ref={isLatestUserMsg ? latestUserMsgRef : undefined}
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
                        className={`prose dark:prose-invert ${message.role === "user" ? "dark:text-black!" : ""}`}
                      >
                        <MemoizedMarkdown
                          id={message.id}
                          content={messageText}
                        />
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
                          label="Copy"
                          icon={<Copy className="h-3 w-3" />}
                          onClick={() => {
                            navigator.clipboard.writeText(messageText);
                            toast({
                              title: "Copied",
                              description: "Message copied to clipboard",
                            });
                          }}
                        />
                        <Action
                          label="Retry"
                          icon={<RotateCcw className="h-3 w-3" />}
                          onClick={() => regenerate()}
                        />
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

      <Form {...form}>
        <form
          onSubmit={onFormSubmit}
          className="mx-auto flex w-full gap-2 px-4 pb-16 md:max-w-3xl md:pb-16"
        >
          <div className="flex w-full items-end gap-2">
            <div className="w-full flex-1">
              <CustomTextarea
                control={form.control}
                name="message"
                label=""
                placeholder={
                  error || errorMessage
                    ? "Edit your message and try again..."
                    : "Type your message..."
                }
                variant="bordered"
                minRows={1}
                maxRows={6}
                fullWidth={true}
                disableAutosize={false}
              />
            </div>
            <CustomButton
              type="submit"
              ariaLabel={
                status === "streaming" || status === "submitted"
                  ? "Generating response..."
                  : "Send message"
              }
              isDisabled={
                status === "streaming" ||
                status === "submitted" ||
                !messageValue?.trim()
              }
              className="bg-primary text-primary-foreground hover:bg-primary/90 dark:bg-primary/90 flex h-10 w-10 shrink-0 items-center justify-center rounded-lg p-2 disabled:opacity-50"
            >
              {status === "streaming" || status === "submitted" ? (
                <Square className="h-5 w-5" />
              ) : (
                <Play className="h-5 w-5" />
              )}
            </CustomButton>
          </div>
        </form>
      </Form>
    </div>
  );
};

export default Chat;
