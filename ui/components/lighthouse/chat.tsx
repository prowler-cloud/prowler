"use client";

import { useChat } from "@ai-sdk/react";
import Link from "next/link";
import { useEffect, useRef } from "react";

import { MemoizedMarkdown } from "@/components/lighthouse/memoized-markdown";
import { CustomButton } from "@/components/ui/custom";

interface SuggestedAction {
  title: string;
  label: string;
  action: string;
}

interface ChatProps {
  hasApiKey: boolean;
}

export const Chat = ({ hasApiKey }: ChatProps) => {
  const { messages, input, handleSubmit, handleInputChange, append, status } =
    useChat({
      api: "/api/lighthouse/analyst",
      credentials: "same-origin",
      experimental_throttle: 100,
      sendExtraMessageFields: true,
      onFinish: () => {
        // Handle chat completion
      },
      onError: () => {
        console.log("An error occurred, please try again!");
      },
    });

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

  const textareaRef = useRef<HTMLTextAreaElement | null>(null);
  const messagesContainerRef = useRef<HTMLDivElement | null>(null);
  const latestUserMsgRef = useRef<HTMLDivElement | null>(null);

  useEffect(() => {
    if (messagesContainerRef.current && latestUserMsgRef.current) {
      const container = messagesContainerRef.current;
      const userMsg = latestUserMsgRef.current;
      const containerPadding = 16; // p-4 in Tailwind = 16px
      container.scrollTop =
        userMsg.offsetTop - container.offsetTop - containerPadding;
    }
  }, [messages]);

  const handleAutoResizeInputChange = (
    e: React.ChangeEvent<HTMLTextAreaElement>,
  ) => {
    handleInputChange(e);
    const textarea = textareaRef.current;
    if (textarea) {
      textarea.style.height = "auto";
      textarea.style.height = textarea.scrollHeight + "px";
      if (textarea.scrollHeight > textarea.clientHeight + 1) {
        textarea.style.overflowY = "auto";
      } else {
        textarea.style.overflowY = "hidden";
      }
    }
  };

  return (
    <div className="relative flex h-[calc(100vh-theme(spacing.16))] min-w-0 flex-col bg-background">
      {!hasApiKey && (
        <div className="absolute inset-0 z-50 flex items-center justify-center bg-background/80 backdrop-blur-sm">
          <div className="bg-card max-w-md rounded-lg p-6 text-center shadow-lg">
            <h3 className="mb-2 text-lg font-semibold">
              OpenAI API Key Required
            </h3>
            <p className="text-muted-foreground mb-4">
              Please configure your OpenAI API key to use the Lighthouse Cloud
              Security Analyst.
            </p>
            <Link
              href="/lighthouse/config"
              className="inline-flex items-center justify-center rounded-md bg-primary px-4 py-2 text-sm font-medium text-primary-foreground hover:bg-primary/90"
            >
              Configure API Key
            </Link>
          </div>
        </div>
      )}

      {messages.length === 0 ? (
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

      <form
        onSubmit={handleSubmit}
        className="mx-auto flex w-full gap-2 px-4 pb-4 md:max-w-3xl md:pb-6"
      >
        <div className="flex w-full items-end gap-2">
          <textarea
            ref={textareaRef}
            value={input}
            onChange={handleAutoResizeInputChange}
            placeholder="Type your message..."
            rows={1}
            className="w-full flex-1 resize-none overflow-hidden rounded-lg border bg-background px-3 py-2 focus:outline-none"
            style={{ minHeight: "40px", maxHeight: "160px" }}
            onKeyDown={(e) => {
              if ((e.metaKey || e.ctrlKey) && e.key === "Enter") {
                e.preventDefault();
                handleSubmit();
              }
            }}
          />
          <CustomButton
            type="submit"
            ariaLabel={
              status === "submitted" ? "Stop generation" : "Send message"
            }
            isDisabled={status === "submitted" || !input.trim()}
            className="flex h-10 w-10 flex-shrink-0 items-center justify-center rounded-lg bg-primary p-2 text-primary-foreground hover:bg-primary/90 disabled:opacity-50"
          >
            {status === "submitted" ? <span>■</span> : <span>➤</span>}
          </CustomButton>
        </div>
      </form>
    </div>
  );
};

export default Chat;
