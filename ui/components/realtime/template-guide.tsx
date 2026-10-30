"use client";

import { Download } from "lucide-react";
import type { ReactNode } from "react";

import { Button } from "@/components/shadcn/button/button";
import { CodeSnippet } from "@/components/shadcn/code-snippet/code-snippet";
import {
  Tabs,
  TabsContent,
  TabsList,
  TabsTrigger,
} from "@/components/shadcn/tabs/tabs";
import type { RealtimeTemplate } from "@/lib/realtime/templates";

interface TemplateGuideProps {
  /** What the person does in their AWS account, in order. */
  steps: ReactNode[];
  cloudformation: RealtimeTemplate;
  terraform: RealtimeTemplate;
}

const download = (template: RealtimeTemplate) => {
  const url = URL.createObjectURL(
    new Blob([template.content], { type: "text/plain" }),
  );
  const link = document.createElement("a");
  link.href = url;
  link.download = template.filename;
  link.click();
  URL.revokeObjectURL(url);
};

/**
 * Tells the person what to do in their own AWS account: numbered steps and the
 * template to apply, as CloudFormation or Terraform, ready to copy or download.
 */
export function TemplateGuide({
  steps,
  cloudformation,
  terraform,
}: TemplateGuideProps) {
  return (
    <div className="flex flex-col gap-4">
      <ol className="text-text-neutral-secondary flex list-decimal flex-col gap-1.5 pl-5 text-sm">
        {steps.map((step, index) => (
          <li key={index}>{step}</li>
        ))}
      </ol>
      <Tabs defaultValue="cloudformation">
        <TabsList>
          <TabsTrigger value="cloudformation">CloudFormation</TabsTrigger>
          <TabsTrigger value="terraform">Terraform</TabsTrigger>
        </TabsList>
        {[
          ["cloudformation", cloudformation],
          ["terraform", terraform],
        ].map(([value, template]) => {
          const item = template as RealtimeTemplate;
          return (
            <TabsContent key={value as string} value={value as string}>
              <div className="flex flex-col gap-2">
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <code className="text-xs">{item.filename}</code>
                  <div className="flex items-center gap-2">
                    <CodeSnippet
                      value={item.content}
                      hideCode
                      ariaLabel={`Copy ${item.filename}`}
                    />
                    <Button
                      variant="outline"
                      size="sm"
                      onClick={() => download(item)}
                    >
                      <Download className="size-4" /> Download
                    </Button>
                  </div>
                </div>
                <pre
                  className="bg-bg-neutral-tertiary border-border-neutral-tertiary max-h-96 overflow-auto rounded-lg border p-3 text-xs"
                  tabIndex={0}
                  aria-label={`${item.filename} contents`}
                >
                  {item.content}
                </pre>
              </div>
            </TabsContent>
          );
        })}
      </Tabs>
    </div>
  );
}
