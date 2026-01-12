"use client";

import { useCallback, useRef, useState } from "react";

import { FileIcon, UploadCloudIcon, XIcon } from "@/components/icons";
import { Button } from "@/components/shadcn/button/button";
import { cn } from "@/lib/utils";

import type { ScanImportDropzoneProps } from "./types";
import {
  ACCEPTED_FILE_EXTENSIONS,
  ACCEPTED_MIME_TYPES,
  MAX_IMPORT_FILE_SIZE,
} from "./types";

/**
 * Formats file size in bytes to a human-readable string.
 */
function formatFileSize(bytes: number): string {
  if (bytes === 0) return "0 Bytes";
  const k = 1024;
  const sizes = ["Bytes", "KB", "MB", "GB"];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return `${parseFloat((bytes / Math.pow(k, i)).toFixed(2))} ${sizes[i]}`;
}

/**
 * Validates if a file is acceptable for import.
 */
function isValidFile(
  file: File,
  maxSize: number,
): { valid: boolean; error?: string } {
  // Check file size
  if (file.size > maxSize) {
    return {
      valid: false,
      error: `File size exceeds maximum of ${formatFileSize(maxSize)}`,
    };
  }

  // Check file type by extension or MIME type
  const fileName = file.name.toLowerCase();
  const mimeType = file.type || "";

  const hasValidExtension = ACCEPTED_FILE_EXTENSIONS.some((ext) =>
    fileName.endsWith(ext),
  );
  const hasValidMimeType = ACCEPTED_MIME_TYPES.includes(
    mimeType as (typeof ACCEPTED_MIME_TYPES)[number],
  );

  if (!hasValidExtension && !hasValidMimeType) {
    return {
      valid: false,
      error: "File must be JSON or CSV format",
    };
  }

  return { valid: true };
}

/**
 * Dropzone component for uploading scan result files.
 * Supports drag-and-drop and click-to-select functionality.
 */
export function ScanImportDropzone({
  file,
  onFileSelect,
  disabled = false,
  acceptedTypes = [".json", ".csv"],
  maxSize = MAX_IMPORT_FILE_SIZE,
}: ScanImportDropzoneProps) {
  const [isDragOver, setIsDragOver] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const inputRef = useRef<HTMLInputElement>(null);

  const handleDragOver = useCallback(
    (e: React.DragEvent<HTMLDivElement>) => {
      e.preventDefault();
      e.stopPropagation();
      if (!disabled) {
        setIsDragOver(true);
      }
    },
    [disabled],
  );

  const handleDragLeave = useCallback((e: React.DragEvent<HTMLDivElement>) => {
    e.preventDefault();
    e.stopPropagation();
    setIsDragOver(false);
  }, []);

  const handleDrop = useCallback(
    (e: React.DragEvent<HTMLDivElement>) => {
      e.preventDefault();
      e.stopPropagation();
      setIsDragOver(false);

      if (disabled) return;

      const droppedFile = e.dataTransfer.files?.[0];
      if (!droppedFile) return;

      const validation = isValidFile(droppedFile, maxSize);
      if (!validation.valid) {
        setError(validation.error || "Invalid file");
        return;
      }

      setError(null);
      onFileSelect(droppedFile);
    },
    [disabled, maxSize, onFileSelect],
  );

  const handleFileChange = useCallback(
    (e: React.ChangeEvent<HTMLInputElement>) => {
      const selectedFile = e.target.files?.[0];
      if (!selectedFile) return;

      const validation = isValidFile(selectedFile, maxSize);
      if (!validation.valid) {
        setError(validation.error || "Invalid file");
        // Reset input
        if (inputRef.current) {
          inputRef.current.value = "";
        }
        return;
      }

      setError(null);
      onFileSelect(selectedFile);
    },
    [maxSize, onFileSelect],
  );

  const handleClick = useCallback(() => {
    if (!disabled) {
      inputRef.current?.click();
    }
  }, [disabled]);

  const handleRemoveFile = useCallback(
    (e: React.MouseEvent) => {
      e.stopPropagation();
      onFileSelect(null);
      setError(null);
      if (inputRef.current) {
        inputRef.current.value = "";
      }
    },
    [onFileSelect],
  );

  const handleKeyDown = useCallback(
    (e: React.KeyboardEvent<HTMLDivElement>) => {
      if (e.key === "Enter" || e.key === " ") {
        e.preventDefault();
        handleClick();
      }
    },
    [handleClick],
  );

  return (
    <div className="w-full">
      <input
        ref={inputRef}
        type="file"
        accept={acceptedTypes.join(",")}
        onChange={handleFileChange}
        disabled={disabled}
        className="hidden"
        aria-label="Upload scan results file"
      />

      {file ? (
        // File selected state
        <div
          className={cn(
            "flex items-center justify-between gap-3 rounded-lg border border-solid",
            "border-border-neutral-secondary bg-bg-neutral-secondary p-4",
            "transition-all duration-200 ease-in-out",
            disabled && "cursor-not-allowed opacity-50",
          )}
        >
          <div className="flex min-w-0 items-center gap-3">
            <div className="bg-bg-neutral-tertiary flex h-10 w-10 shrink-0 items-center justify-center rounded-md">
              <FileIcon className="text-text-neutral-secondary h-5 w-5" />
            </div>
            <div className="min-w-0">
              <p className="text-text-neutral-primary truncate text-sm font-medium">
                {file.name}
              </p>
              <p className="text-text-neutral-secondary text-xs">
                {formatFileSize(file.size)}
              </p>
            </div>
          </div>
          <Button
            type="button"
            variant="ghost"
            size="icon-sm"
            onClick={handleRemoveFile}
            disabled={disabled}
            aria-label="Remove file"
          >
            <XIcon className="h-4 w-4" />
          </Button>
        </div>
      ) : (
        // Dropzone state - dashed border with hover effects
        <div
          role="button"
          tabIndex={disabled ? -1 : 0}
          onClick={handleClick}
          onKeyDown={handleKeyDown}
          onDragOver={handleDragOver}
          onDragLeave={handleDragLeave}
          onDrop={handleDrop}
          className={cn(
            // Base styles: dashed border, rounded corners, padding
            "flex flex-col items-center justify-center gap-3 rounded-lg p-8",
            "border-2 border-dashed",
            // Default colors
            "border-border-neutral-secondary bg-bg-neutral-secondary",
            // Smooth transitions for all interactive states
            "transition-all duration-200 ease-in-out",
            // Hover state: darker border and subtle background change
            "hover:border-border-neutral-tertiary hover:bg-bg-neutral-tertiary",
            "hover:shadow-sm",
            // Active/drag-over state: primary color highlight
            isDragOver && "border-button-primary bg-button-primary/5 shadow-md",
            // Disabled state: reduced opacity, no hover effects
            disabled && [
              "cursor-not-allowed opacity-50",
              "hover:border-border-neutral-secondary hover:bg-bg-neutral-secondary hover:shadow-none",
            ],
            // Error state: red border
            error && "border-bg-fail hover:border-bg-fail",
            // Focus state: visible ring for accessibility
            "focus-visible:ring-button-primary/50 focus:outline-none focus-visible:ring-2 focus-visible:ring-offset-2",
          )}
        >
          <div
            className={cn(
              "flex h-12 w-12 items-center justify-center rounded-full",
              "bg-bg-neutral-tertiary",
              "transition-all duration-200 ease-in-out",
              isDragOver && "bg-button-primary/10 scale-110",
            )}
          >
            <UploadCloudIcon
              className={cn(
                "text-text-neutral-secondary h-6 w-6",
                "transition-colors duration-200 ease-in-out",
                isDragOver && "text-button-primary",
              )}
            />
          </div>
          <div className="text-center">
            <p className="text-text-neutral-primary text-sm font-medium">
              {isDragOver ? "Drop file here" : "Drag and drop your scan file"}
            </p>
            <p className="text-text-neutral-secondary mt-1 text-xs">
              or click to browse
            </p>
          </div>
          <p className="text-text-neutral-tertiary text-xs">
            Supports JSON and CSV formats (max {formatFileSize(maxSize)})
          </p>
        </div>
      )}

      {error && (
        <p className="text-bg-fail mt-2 text-xs" role="alert">
          {error}
        </p>
      )}
    </div>
  );
}
