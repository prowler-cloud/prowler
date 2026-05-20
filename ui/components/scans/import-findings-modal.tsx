"use client";

import { Info, Upload } from "lucide-react";
import Link from "next/link";
import { type FormEvent, useState } from "react";

import { FieldError, FileUploadDropzone } from "@/components/shadcn";
import { Modal } from "@/components/shadcn/modal";
import { FormButtons } from "@/components/ui/form";
import { toast } from "@/components/ui/toast";

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
  const [error, setError] = useState<string | null>(null);

  const closeModal = () => {
    setFile(null);
    setError(null);
    onOpenChange(false);
  };

  const setSelectedFile = (nextFile?: File) => {
    if (!nextFile) return;
    setFile(nextFile);
    setError(null);
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
      className="gap-2"
    >
      <form onSubmit={handleImport} className="flex flex-col gap-8">
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

        <div className="flex flex-col gap-2">
          <div className="flex items-center gap-2">
            <Upload className="text-text-neutral-secondary size-4" />
            <span className="text-text-neutral-primary text-sm font-medium">
              Import findings from Prowler CLI
            </span>
          </div>

          <FileUploadDropzone
            file={file}
            onFileSelect={setSelectedFile}
            accept=".json,.ocsf.json,application/json"
            title="Drag and drop your findings file here"
            selectText="Select Files"
          />
        </div>

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
