"use client";

import { Download } from "lucide-react";
import type { ReactNode } from "react";

import type { RealtimeTemplate } from "@/app/(prowler)/realtime/_lib/templates";
import { Button } from "@/components/shadcn";
import { CodeSnippet } from "@/components/shadcn/code-snippet/code-snippet";
import {
  Tabs,
  TabsContent,
  TabsList,
  TabsTrigger,
} from "@/components/shadcn/tabs/tabs";

const TEMPLATE_FORMAT = {
  CLOUDFORMATION: "cloudformation",
  TERRAFORM: "terraform",
} as const;

interface TemplateGuideProps {
  /** What to do in the AWS account, in order. */
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

/** Numbered steps plus the template to apply, ready to copy or download. */
export function TemplateGuide({
  steps,
  cloudformation,
  terraform,
}: TemplateGuideProps) {
  const templates = [
    {
      value: TEMPLATE_FORMAT.CLOUDFORMATION,
      label: "CloudFormation",
      template: cloudformation,
    },
    {
      value: TEMPLATE_FORMAT.TERRAFORM,
      label: "Terraform",
      template: terraform,
    },
  ];

  return (
    <div className="flex flex-col gap-3">
      <ol className="text-text-neutral-secondary flex list-decimal flex-col gap-1 pl-5 text-sm">
        {steps.map((step, index) => (
          <li key={index}>{step}</li>
        ))}
      </ol>
      <Tabs defaultValue={TEMPLATE_FORMAT.CLOUDFORMATION}>
        <TabsList>
          {templates.map(({ value, label }) => (
            <TabsTrigger key={value} value={value}>
              {label}
            </TabsTrigger>
          ))}
        </TabsList>
        {templates.map(({ value, template }) => (
          <TabsContent key={value} value={value}>
            <div className="flex flex-col gap-2">
              <div className="flex flex-wrap items-center justify-between gap-2">
                <span className="text-text-neutral-secondary font-mono text-xs">
                  {template.filename}
                </span>
                <Button
                  type="button"
                  variant="outline"
                  size="sm"
                  onClick={() => download(template)}
                >
                  <Download aria-hidden /> Download
                </Button>
              </div>
              <div
                tabIndex={0}
                aria-label={`${template.filename} contents`}
                className="max-h-72 overflow-auto"
              >
                <CodeSnippet
                  value={template.content}
                  multiline
                  ariaLabel={`Copy ${template.filename}`}
                  className="w-full items-start font-mono"
                />
              </div>
            </div>
          </TabsContent>
        ))}
      </Tabs>
    </div>
  );
}
