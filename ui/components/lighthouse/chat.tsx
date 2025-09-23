"use client";

import { useChat } from "@ai-sdk/react";
import { useEffect, useRef, useState } from "react";
import { useForm } from "react-hook-form";

import { MemoizedMarkdown } from "@/components/lighthouse/memoized-markdown";
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

  const {
    messages,
    handleSubmit,
    handleInputChange,
    append,
    status,
    error,
    setMessages,
  } = useChat({
    api: "/api/lighthouse/analyst",
    credentials: "same-origin",
    experimental_throttle: 100,
    sendExtraMessageFields: true,
    onFinish: (message) => {
      // There is no specific way to output the error message from langgraph supervisor
      // Hence, all error messages are sent as normal messages with the prefix [LIGHTHOUSE_ANALYST_ERROR]:
      // Detect error messages sent from backend using specific prefix and display the error
      if (message.content?.startsWith("[LIGHTHOUSE_ANALYST_ERROR]:")) {
        const errorText = message.content
          .replace("[LIGHTHOUSE_ANALYST_ERROR]:", "")
          .trim();
        setErrorMessage(errorText);
        // Remove error message from chat history
        setMessages((prev) =>
          prev.filter(
            (m) => !m.content?.startsWith("[LIGHTHOUSE_ANALYST_ERROR]:"),
          ),
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
          form.setValue("message", lastUserMessage.content);
          // Remove the last user message from history since it's now in the input
          return currentMessages.slice(0, -1);
        }

        return currentMessages;
      });
    }
  }, [errorMessage, form, setMessages]);

  // Sync form value with chat input
  useEffect(() => {
    const syntheticEvent = {
      target: { value: messageValue },
    } as React.ChangeEvent<HTMLInputElement>;
    handleInputChange(syntheticEvent);
  }, [messageValue, handleInputChange]);

  // Reset form when message is sent
  useEffect(() => {
    if (status === "submitted") {
      form.reset({ message: "" });
    }
  }, [status, form]);

  const onFormSubmit = form.handleSubmit((data) => {
    if (data.message.trim()) {
      // Clear error on new submission
      setErrorMessage(null);
      handleSubmit();
    }
  });

  // Global keyboard shortcut handler
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === "Enter" && !e.shiftKey) {
        e.preventDefault();
        if (messageValue?.trim()) {
          onFormSubmit();
        }
      }
    };

    document.addEventListener("keydown", handleKeyDown);
    return () => document.removeEventListener("keydown", handleKeyDown);
  }, [messageValue, onFormSubmit]);

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

  return (
    <div className="relative flex h-[calc(100vh-theme(spacing.16))] min-w-0 flex-col bg-background">
      {shouldDisableChat && (
        <div className="absolute inset-0 z-50 flex items-center justify-center bg-background/80 backdrop-blur-sm">
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
              className="inline-flex items-center justify-center rounded-md bg-primary px-4 py-2 text-primary-foreground hover:bg-primary/90"
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
            <div className="flex-shrink-0">
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
                    append({
                      role: "user",
                      content: action.action,
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
          className="flex-1 space-y-4 overflow-y-auto p-4"
          ref={messagesContainerRef}
        >
          {messages.map((message, idx) => {
            const lastUserIdx = messages
              .map((m, i) => (m.role === "user" ? i : -1))
              .filter((i) => i !== -1)
              .pop();
            const isLatestUserMsg =
              message.role === "user" && lastUserIdx === idx;
            return (
              <div
                key={message.id}
                ref={isLatestUserMsg ? latestUserMsgRef : undefined}
                className={`flex ${
                  message.role === "user" ? "justify-end" : "justify-start"
                }`}
              >
                <div
                  className={`max-w-[80%] rounded-lg px-4 py-2 ${
                    message.role === "user"
                      ? "bg-primary text-primary-foreground dark:!text-black"
                      : "bg-muted"
                  }`}
                >
                  <div
                    className={`prose dark:prose-invert ${message.role === "user" ? "dark:!text-black" : ""}`}
                  >
                    <MemoizedMarkdown
                      id={message.id}
                      content={message.content}
                    />
                  </div>
                </div>
              </div>
            );
          })}
          {status === "submitted" && (
            <div className="flex justify-start">
              <div className="bg-muted max-w-[80%] rounded-lg px-4 py-2">
                <div className="animate-pulse">Thinking...</div>
              </div>
            </div>
          )}
        </div>
      )}

      <Form {...form}>
        <form
          onSubmit={onFormSubmit}
          className="mx-auto flex w-full gap-2 px-4 pb-4 md:max-w-3xl md:pb-6"
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
                status === "submitted" ? "Stop generation" : "Send message"
              }
              isDisabled={status === "submitted" || !messageValue?.trim()}
              className="flex h-10 w-10 flex-shrink-0 items-center justify-center rounded-lg bg-primary p-2 text-primary-foreground hover:bg-primary/90 disabled:opacity-50 dark:bg-primary/90"
            >
              {status === "submitted" ? <span>■</span> : <span>➤</span>}
            </CustomButton>
          </div>
        </form>
      </Form>
    </div>
  );
};

export default Chat;
