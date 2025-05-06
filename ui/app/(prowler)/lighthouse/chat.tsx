"use client";

import { useChat } from "@ai-sdk/react";
import { useRef } from "react";

import { MemoizedMarkdown } from "@/components/memoized-markdown";

// Add this interface above the Chat component
interface SuggestedAction {
  title: string;
  label: string;
  action: string;
}

export default function Chat() {
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

  const handleAutoResizeInputChange = (e: React.ChangeEvent<HTMLTextAreaElement>) => {
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
    <div className="flex h-[calc(100vh-theme(spacing.16))] min-w-0 flex-col bg-background">
      {messages.length === 0 ? (
        <div className="flex flex-1 items-center justify-center p-4">
          <div className="w-full max-w-2xl">
            <h2 className="mb-4 text-center font-sans text-xl">Suggestions</h2>
            <div className="grid gap-2 sm:grid-cols-2">
              {suggestedActions.map((action, index) => (
                <button
                  key={`suggested-action-${index}`}
                  onClick={() => {
                    append({
                      role: "user",
                      content: action.action,
                    });
                  }}
                  className="hover:bg-muted flex h-auto w-full flex-col items-start justify-start rounded-xl border bg-gray-50 px-4 py-3.5 text-left font-sans text-sm dark:bg-gray-900"
                >
                  <span>{action.title}</span>
                  <span className="text-muted-foreground">{action.label}</span>
                </button>
              ))}
            </div>
          </div>
        </div>
      ) : (
        <div className="flex-1 space-y-4 overflow-y-auto p-4">
          {messages.map((message) => (
            <div
              key={message.id}
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
                  <MemoizedMarkdown id={message.id} content={message.content} />
                </div>
              </div>
            </div>
          ))}
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
            className="w-full flex-1 px-3 py-2 focus:outline-none resize-none overflow-hidden rounded-lg border bg-background"
            style={{ minHeight: "40px", maxHeight: "160px" }}
            onKeyDown={(e) => {
              if ((e.metaKey || e.ctrlKey) && e.key === "Enter") {
                e.preventDefault();
                handleSubmit();
              }
            }}
          />
          <button
            type="submit"
            disabled={status === "submitted" || !input.trim()}
            className="rounded-lg bg-primary p-2 text-primary-foreground hover:bg-primary/90 disabled:opacity-50 flex-shrink-0 h-10 w-10 flex items-center justify-center"
          >
            {status === "submitted" ? <span>■</span> : <span>➤</span>}
          </button>
        </div>
      </form>
    </div>
  );
}
