"use client";

import { zodResolver } from "@hookform/resolvers/zod";
import { useCallback, useState } from "react";
import { useForm } from "react-hook-form";
import { z } from "zod";

import { Checkbox } from "@/components/shadcn/checkbox/checkbox";
import { Label } from "@/components/ui";
import {
  Form,
  FormControl,
  FormDescription,
  FormField,
  FormItem,
  FormLabel,
  FormMessage,
} from "@/components/ui/form";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { cn } from "@/lib/utils";
import { getProviderDisplayName, ProviderType } from "@/types/providers";

import { ScanImportDropzone } from "./scan-import-dropzone";
import type { ScanImportFormData, ScanImportFormProps } from "./types";
import { ACCEPTED_MIME_TYPES, MAX_IMPORT_FILE_SIZE } from "./types";

/**
 * Sentinel value for auto-detect provider option.
 * Used because Radix UI Select doesn't allow empty string values.
 */
const AUTO_DETECT_VALUE = "__auto_detect__";

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
      },
    )
    .refine(
      (file) => {
        if (!file) return true;
        const mimeType = file.type || "";
        const fileName = file.name.toLowerCase();
        // Check MIME type or file extension
        return (
          ACCEPTED_MIME_TYPES.includes(
            mimeType as (typeof ACCEPTED_MIME_TYPES)[number],
          ) ||
          fileName.endsWith(".json") ||
          fileName.endsWith(".csv")
        );
      },
      {
        message: "File must be JSON or CSV format",
      },
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
      providerId: AUTO_DETECT_VALUE,
      createProvider: true,
    },
  });

  const handleFileSelect = useCallback(
    (file: File | null) => {
      setSelectedFile(file);
      form.setValue("file", file, { shouldValidate: true });
    },
    [form],
  );

  const handleSubmit = useCallback(
    (values: ScanImportFormValues) => {
      // Convert sentinel value back to undefined for API call
      const providerId =
        values.providerId === AUTO_DETECT_VALUE ? undefined : values.providerId;

      const formData: ScanImportFormData = {
        file: values.file,
        providerId: providerId || undefined,
        createProvider: values.createProvider,
      };
      onSubmit(formData);
    },
    [onSubmit],
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
    {} as Record<ProviderType, typeof providers>,
  );

  const sortedProviderTypes = Object.keys(
    groupedProviders,
  ).sort() as ProviderType[];

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
              <FormLabel className="text-text-neutral-primary text-sm font-medium">
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
              <FormLabel className="text-text-neutral-primary text-sm font-medium">
                Provider (Optional)
              </FormLabel>
              <FormDescription className="text-text-neutral-secondary text-xs">
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
                      "focus:ring-button-primary/50",
                    )}
                  >
                    <SelectValue placeholder="Auto-detect from scan data" />
                  </SelectTrigger>
                </FormControl>
                <SelectContent>
                  {/* Auto-detect option with sentinel value */}
                  <SelectItem value={AUTO_DETECT_VALUE}>
                    <span className="text-text-neutral-secondary">
                      Auto-detect from scan data
                    </span>
                  </SelectItem>

                  {/* Grouped providers by type */}
                  {sortedProviderTypes.map((providerType) => (
                    <div key={providerType}>
                      <div className="text-text-neutral-tertiary px-2 py-1.5 text-xs font-semibold">
                        {getProviderDisplayName(providerType)}
                      </div>
                      {groupedProviders[providerType].map((provider) => (
                        <SelectItem key={provider.id} value={provider.id}>
                          <div className="flex items-center gap-2">
                            <span className="truncate">
                              {provider.alias || provider.uid}
                            </span>
                            {!provider.alias && (
                              <span className="text-text-neutral-tertiary text-xs">
                                ({provider.uid})
                              </span>
                            )}
                          </div>
                        </SelectItem>
                      ))}
                    </div>
                  ))}

                  {providers.length === 0 && (
                    <div className="text-text-neutral-secondary px-2 py-4 text-center text-sm">
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
            <FormItem className="flex flex-row items-start space-y-0 space-x-3">
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
                    "cursor-pointer text-sm font-medium",
                    isSubmitting && "cursor-not-allowed opacity-50",
                  )}
                >
                  Create provider if not found
                </Label>
                <p className="text-text-neutral-secondary text-xs">
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
            "focus:ring-button-primary/50 focus:ring-2 focus:ring-offset-2 focus:outline-none",
            "disabled:cursor-not-allowed disabled:opacity-50",
            "transition-all duration-200 ease-in-out",
          )}
        >
          {isSubmitting ? "Importing..." : "Import Scan Results"}
        </button>
      </form>
    </Form>
  );
}
