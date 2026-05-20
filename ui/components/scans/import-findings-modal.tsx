"use client";

import { FileUp, Info, Upload } from "lucide-react";
import Link from "next/link";
import { type DragEvent, type FormEvent, useState } from "react";

import { FieldError } from "@/components/shadcn";
import { Modal } from "@/components/shadcn/modal";
import { FormButtons } from "@/components/ui/form";
import { toast } from "@/components/ui/toast";
import { cn } from "@/lib";

interface ImportFindingsModalProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
}

const IMPORT_DOCS_URL = "/user-guide/tutorials/prowler-app-import-findings";

export function ImportFindingsModal({
  open,
  onOpenChange,
}: ImportFindingsModalProps) {
  const [file, setFile] = useState<File | null>(null);
  const [isDragging, setIsDragging] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const closeModal = () => {
    setFile(null);
    setError(null);
    setIsDragging(false);
    onOpenChange(false);
  };

  const setSelectedFile = (nextFile?: File) => {
    if (!nextFile) return;
    setFile(nextFile);
    setError(null);
  };

  const handleDrop = (event: DragEvent<HTMLLabelElement>) => {
    event.preventDefault();
    setIsDragging(false);
    setSelectedFile(event.dataTransfer.files[0]);
  };

  const handleImport = (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();

    if (!file) {
      setError("Select a findings file to import.");
      return;
    }

    toast({
      variant: "destructive",
      title: "Import unavailable",
      description: "The ingestions action is not available in the UI yet.",
    });
  };

  return (
    <Modal
      open={open}
      onOpenChange={(nextOpen) => {
        if (!nextOpen) closeModal();
        else onOpenChange(true);
      }}
      title="Import Prowler CLI Findings"
      size="xl"
    >
      <form onSubmit={handleImport} className="flex flex-col gap-5">
        <div className="border-border-neutral-secondary bg-bg-neutral-tertiary flex items-center gap-2 rounded-md border px-3 py-2">
          <Info className="text-text-neutral-secondary size-4" />
          <span className="text-text-neutral-secondary text-xs">
            For help importing Prowler CLI files visit{" "}
            <Link
              href={IMPORT_DOCS_URL}
              className="text-button-tertiary hover:text-button-tertiary-hover font-medium"
            >
              Prowler Docs
            </Link>
          </span>
        </div>

        <div className="flex items-center gap-2">
          <Upload className="text-text-neutral-secondary size-4" />
          <span className="text-text-neutral-primary text-sm font-medium">
            Import findings from Prowler CLI
          </span>
        </div>

        <label
          htmlFor="import-findings-file"
          onDragOver={(event) => {
            event.preventDefault();
            setIsDragging(true);
          }}
          onDragLeave={() => setIsDragging(false)}
          onDrop={handleDrop}
          className={cn(
            "border-border-neutral-tertiary bg-bg-neutral-primary hover:bg-bg-neutral-tertiary flex min-h-[132px] cursor-pointer flex-col items-center justify-center gap-2 rounded-lg border border-dashed px-4 py-8 text-center transition-colors",
            isDragging &&
              "border-border-input-primary-press bg-bg-neutral-tertiary",
          )}
        >
          <FileUp className="text-text-neutral-secondary size-6" />
          <span className="text-text-neutral-primary text-sm font-medium">
            {file ? file.name : "Drag and drop your findings file here"}
          </span>
          <span className="text-text-neutral-secondary text-xs">
            {file ? `${Math.ceil(file.size / 1024).toLocaleString()} KB` : "or"}
          </span>
          {!file && (
            <span className="text-button-tertiary text-sm font-medium">
              Select Files
            </span>
          )}
          <input
            id="import-findings-file"
            type="file"
            accept=".json,.ocsf.json,application/json"
            className="sr-only"
            onChange={(event) => setSelectedFile(event.target.files?.[0])}
          />
        </label>

        {error && <FieldError>{error}</FieldError>}

        <FormButtons
          onCancel={closeModal}
          submitText="Import Findings"
          loadingText="Importing..."
          rightIcon={<Upload className="size-4" />}
        />
      </form>
    </Modal>
  );
}
