"use client";

import { zodResolver } from "@hookform/resolvers/zod";
import { useCallback, useState } from "react";
import { useForm } from "react-hook-form";
import { z } from "zod";

import { Checkbox } from "@/components/shadcn/checkbox/checkbox";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import {
  Form,
  FormControl,
  FormDescription,
  FormField,
  FormItem,
  FormLabel,
  FormMessage,
} from "@/components/ui/form";
import { Label } from "@/components/ui";
import { cn } from "@/lib/utils";
import { getProviderDisplayName, ProviderType } from "@/types/providers";

import { ScanImportDropzone } from "./scan-import-dropzone";
import type { ScanImportFormData, ScanImportFormProps } from "./types";
import {
  ACCEPTED_MIME_TYPES,
  MAX_IMPORT_FILE_SIZE,
} from "./types";

/**
 * Zod schema for the scan import form.
 *
 * Validates:
 * - file: Required, must be JSON or CSV format, max 50MB
 * - providerId: Optional UUID string
 * - createProvider: Boolean, defaults to true
 */
export const scanImportFormSchema = z.object({
  file: z
    .instanceof(File, { message: "Please select a file to import" })
    .nullable()
    .refine((file) => file !== null, {
      message: "Please select a file to import",
    })
    .refine(
      (file) => {
        if (!file) return true;
        return file.size <= MAX_IMPORT_FILE_SIZE;
      },
      {
        message: `File size exceeds maximum of ${MAX_IMPORT_FILE_SIZE / (1024 * 1024)}MB`,
      }
    )
    .refine(
      (file) => {
        if (!file) return true;
        const mimeType = file.type || "";
        const fileName = file.name.toLowerCase();
        // Check MIME type or file extension
        return (
          ACCEPTED_MIME_TYPES.includes(
            mimeType as (typeof ACCEPTED_MIME_TYPES)[number]
          ) ||
          fileName.endsWith(".json") ||
          fileName.endsWith(".csv")
        );
      },
      {
        message: "File must be JSON or CSV format",
      }
    ),
  providerId: z.string().optional(),
  createProvider: z.boolean(),
});

/**
 * Type inferred from the scan import form schema.
 */
export type ScanImportFormValues = z.infer<typeof scanImportFormSchema>;

/**
 * Form component for importing scan results.
 *
 * Includes:
 * - File dropzone for selecting JSON/CSV files
 * - Optional provider selection dropdown
 * - Checkbox to create provider if not found
 */
export function ScanImportForm({
  onSubmit,
  isSubmitting = false,
  providers = [],
}: ScanImportFormProps) {
  const [selectedFile, setSelectedFile] = useState<File | null>(null);

  const form = useForm<ScanImportFormValues>({
    resolver: zodResolver(scanImportFormSchema),
    defaultValues: {
      file: null,
      providerId: "",
      createProvider: true,
    },
  });

  const handleFileSelect = useCallback(
    (file: File | null) => {
      setSelectedFile(file);
      form.setValue("file", file, { shouldValidate: true });
    },
    [form]
  );

  const handleSubmit = useCallback(
    (values: ScanImportFormValues) => {
      const formData: ScanImportFormData = {
        file: values.file,
        providerId: values.providerId || undefined,
        createProvider: values.createProvider,
      };
      onSubmit(formData);
    },
    [onSubmit]
  );

  // Group providers by type for better organization
  const groupedProviders = providers.reduce(
    (acc, provider) => {
      const type = provider.provider;
      if (!acc[type]) {
        acc[type] = [];
      }
      acc[type].push(provider);
      return acc;
    },
    {} as Record<ProviderType, typeof providers>
  );

  const sortedProviderTypes = Object.keys(groupedProviders).sort() as ProviderType[];

  return (
    <Form {...form}>
      <form
        onSubmit={form.handleSubmit(handleSubmit)}
        className="flex flex-col gap-6"
      >
        {/* File Upload Section */}
        <FormField
          control={form.control}
          name="file"
          render={({ fieldState }) => (
            <FormItem>
              <FormLabel className="text-sm font-medium text-text-neutral-primary">
                Scan Results File
              </FormLabel>
              <FormControl>
                <ScanImportDropzone
                  file={selectedFile}
                  onFileSelect={handleFileSelect}
                  disabled={isSubmitting}
                />
              </FormControl>
              {fieldState.error && (
                <FormMessage>{fieldState.error.message}</FormMessage>
              )}
            </FormItem>
          )}
        />

        {/* Provider Selection Section */}
        <FormField
          control={form.control}
          name="providerId"
          render={({ field }) => (
            <FormItem>
              <FormLabel className="text-sm font-medium text-text-neutral-primary">
                Provider (Optional)
              </FormLabel>
              <FormDescription className="text-xs text-text-neutral-secondary">
                Associate the import with an existing provider, or leave empty
                to auto-detect from the scan data.
              </FormDescription>
              <Select
                onValueChange={field.onChange}
                value={field.value}
                disabled={isSubmitting}
              >
                <FormControl>
                  <SelectTrigger
                    className={cn(
                      "w-full",
                      "border-border-neutral-secondary bg-bg-neutral-secondary",
                      "hover:border-border-neutral-tertiary",
                      "focus:ring-button-primary/50"
                    )}
                  >
                    <SelectValue placeholder="Auto-detect from scan data" />
                  </SelectTrigger>
                </FormControl>
                <SelectContent>
                  {/* Empty option for auto-detect */}
                  <SelectItem value="">
                    <span className="text-text-neutral-secondary">
                      Auto-detect from scan data
                    </span>
                  </SelectItem>

                  {/* Grouped providers by type */}
                  {sortedProviderTypes.map((providerType) => (
                    <div key={providerType}>
                      <div className="px-2 py-1.5 text-xs font-semibold text-text-neutral-tertiary">
                        {getProviderDisplayName(providerType)}
                      </div>
                      {groupedProviders[providerType].map((provider) => (
                        <SelectItem key={provider.id} value={provider.id}>
                          <div className="flex items-center gap-2">
                            <span className="truncate">
                              {provider.alias || provider.uid}
                            </span>
                            {!provider.alias && (
                              <span className="text-xs text-text-neutral-tertiary">
                                ({provider.uid})
                              </span>
                            )}
                          </div>
                        </SelectItem>
                      ))}
                    </div>
                  ))}

                  {providers.length === 0 && (
                    <div className="px-2 py-4 text-center text-sm text-text-neutral-secondary">
                      No providers available
                    </div>
                  )}
                </SelectContent>
              </Select>
              <FormMessage />
            </FormItem>
          )}
        />

        {/* Create Provider Checkbox */}
        <FormField
          control={form.control}
          name="createProvider"
          render={({ field }) => (
            <FormItem className="flex flex-row items-start space-x-3 space-y-0">
              <FormControl>
                <Checkbox
                  checked={field.value}
                  onCheckedChange={field.onChange}
                  disabled={isSubmitting}
                  id="createProvider"
                />
              </FormControl>
              <div className="space-y-1 leading-none">
                <Label
                  htmlFor="createProvider"
                  className={cn(
                    "text-sm font-medium cursor-pointer",
                    isSubmitting && "cursor-not-allowed opacity-50"
                  )}
                >
                  Create provider if not found
                </Label>
                <p className="text-xs text-text-neutral-secondary">
                  If the provider from the scan data doesn&apos;t exist, create
                  it automatically.
                </p>
              </div>
            </FormItem>
          )}
        />

        {/* Submit Button */}
        <button
          type="submit"
          disabled={isSubmitting || !selectedFile}
          className={cn(
            "w-full rounded-lg px-4 py-2.5 text-sm font-medium",
            "bg-button-primary text-white",
            "hover:bg-button-primary/90",
            "focus:outline-none focus:ring-2 focus:ring-button-primary/50 focus:ring-offset-2",
            "disabled:cursor-not-allowed disabled:opacity-50",
            "transition-all duration-200 ease-in-out"
          )}
        >
          {isSubmitting ? "Importing..." : "Import Scan Results"}
        </button>
      </form>
    </Form>
  );
}
