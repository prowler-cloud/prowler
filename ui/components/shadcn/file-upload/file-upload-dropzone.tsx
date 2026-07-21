"use client";

import { FileUp } from "lucide-react";
import { type DragEvent, type ReactNode, useId, useState } from "react";

import { cn } from "@/lib/utils";

interface FileUploadDropzoneProps {
  file?: File | null;
  onFileSelect: (file?: File) => void;
  accept?: string;
  className?: string;
  title?: string;
  emptyDescription?: string;
  selectText?: string;
  icon?: ReactNode;
}

export function FileUploadDropzone({
  file,
  onFileSelect,
  accept,
  className,
  title = "Drag and drop your file here",
  emptyDescription = "or",
  selectText = "Select File",
  icon = <FileUp className="text-text-neutral-secondary size-6" />,
}: FileUploadDropzoneProps) {
  const inputId = useId();
  const [isDragging, setIsDragging] = useState(false);

  const handleDrop = (event: DragEvent<HTMLLabelElement>) => {
    event.preventDefault();
    setIsDragging(false);
    onFileSelect(event.dataTransfer.files[0]);
  };

  return (
    <label
      htmlFor={inputId}
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
        className,
      )}
    >
      {icon}
      <span className="text-text-neutral-primary text-sm font-medium">
        {file ? file.name : title}
      </span>
      <span className="text-text-neutral-secondary text-xs">
        {file
          ? `${Math.ceil(file.size / 1024).toLocaleString()} KB`
          : emptyDescription}
      </span>
      {!file && (
        <span className="text-button-tertiary text-sm font-medium">
          {selectText}
        </span>
      )}
      <input
        id={inputId}
        type="file"
        accept={accept}
        className="sr-only"
        onChange={(event) => onFileSelect(event.target.files?.[0])}
      />
    </label>
  );
}
