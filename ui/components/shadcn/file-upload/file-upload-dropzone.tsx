"use client";

import { FileUp } from "lucide-react";
import {
  type ChangeEvent,
  type DragEvent,
  type KeyboardEvent,
  type ReactNode,
  useId,
  useRef,
  useState,
} from "react";

import { cn } from "@/lib/utils";

const KB = 1024;
const MB = KB * 1024;

// Whole KB below 1 MB, one decimal from 1 MB up. Deliberately not
// toLocaleString: a locale-grouped "15.002 KB" reads as 15 KB in es-ES.
function formatFileSize(bytes: number) {
  const kb = Math.ceil(bytes / KB);
  return kb < KB ? `${kb} KB` : `${(bytes / MB).toFixed(1)} MB`;
}

interface FileUploadDropzoneProps {
  file?: File | null;
  onFileSelect: (file?: File) => void;
  accept?: string;
  className?: string;
  title?: string;
  emptyDescription?: string;
  selectText?: string;
  icon?: ReactNode;
  disabled?: boolean;
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
  disabled = false,
}: FileUploadDropzoneProps) {
  const inputId = useId();
  const inputRef = useRef<HTMLInputElement>(null);
  const [isDragging, setIsDragging] = useState(false);

  const handleDrop = (event: DragEvent<HTMLLabelElement>) => {
    event.preventDefault();
    setIsDragging(false);
    if (disabled) return;
    onFileSelect(event.dataTransfer.files[0]);
  };

  const handleKeyDown = (event: KeyboardEvent<HTMLLabelElement>) => {
    if (disabled || (event.key !== "Enter" && event.key !== " ")) return;
    event.preventDefault();
    inputRef.current?.click();
  };

  const handleChange = (event: ChangeEvent<HTMLInputElement>) => {
    onFileSelect(event.target.files?.[0]);
    event.target.value = "";
  };

  return (
    <label
      htmlFor={inputId}
      role="button"
      tabIndex={disabled ? -1 : 0}
      aria-disabled={disabled}
      onKeyDown={handleKeyDown}
      onDragOver={(event) => {
        event.preventDefault();
        if (disabled) return;
        setIsDragging(true);
      }}
      onDragLeave={() => setIsDragging(false)}
      onDrop={handleDrop}
      className={cn(
        "border-border-neutral-tertiary bg-bg-neutral-primary hover:bg-bg-neutral-tertiary flex min-h-[132px] cursor-pointer flex-col items-center justify-center gap-2 rounded-lg border border-dashed px-4 py-8 text-center transition-colors",
        isDragging &&
          "border-border-input-primary-press bg-bg-neutral-tertiary",
        disabled && "hover:bg-bg-neutral-primary cursor-not-allowed opacity-50",
        className,
      )}
    >
      {icon}
      <span className="text-text-neutral-primary text-sm font-medium">
        {file ? file.name : title}
      </span>
      <span className="text-text-neutral-secondary text-xs">
        {file ? formatFileSize(file.size) : emptyDescription}
      </span>
      {!file && (
        <span className="text-button-tertiary text-sm font-medium">
          {selectText}
        </span>
      )}
      <input
        id={inputId}
        ref={inputRef}
        type="file"
        accept={accept}
        disabled={disabled}
        className="sr-only"
        onChange={handleChange}
      />
    </label>
  );
}
