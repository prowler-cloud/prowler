"use client";

import { Select, SelectItem } from "@heroui/select";
import { zodResolver } from "@hookform/resolvers/zod";
import { SaveIcon } from "lucide-react";
import { useRouter } from "next/navigation";
import { useState } from "react";
import { Controller, useForm } from "react-hook-form";
import * as z from "zod";

import {
  createLighthouseConfig,
  updateLighthouseConfig,
} from "@/actions/lighthouse";
import { useToast } from "@/components/ui";
import {
  CustomButton,
  CustomInput,
  CustomTextarea,
} from "@/components/ui/custom";
import { Form } from "@/components/ui/form";

const chatbotConfigSchema = z.object({
  model: z.string().min(1, "Model selection is required"),
  apiKey: z.string().min(1, "API Key is required"),
  businessContext: z
    .string()
    .max(1000, "Business context cannot exceed 1000 characters")
    .optional(),
});

type FormValues = z.infer<typeof chatbotConfigSchema>;

interface ChatbotConfigClientProps {
  initialValues: FormValues;
  configExists: boolean;
}

export const ChatbotConfig = ({
  initialValues,
  configExists: initialConfigExists,
}: ChatbotConfigClientProps) => {
  const router = useRouter();
  const { toast } = useToast();
  const [isLoading, setIsLoading] = useState(false);
  const [configExists, setConfigExists] = useState(initialConfigExists);

  const form = useForm<FormValues>({
    resolver: zodResolver(chatbotConfigSchema),
    defaultValues: initialValues,
    mode: "onChange",
  });

  const onSubmit = async (data: FormValues) => {
    if (isLoading) return;

    // Validate API key: required for new config, or if changing an existing masked key
    if (!configExists && (!data.apiKey || data.apiKey.trim().length === 0)) {
      form.setError("apiKey", {
        type: "manual",
        message: "API Key is required",
      });
      return;
    }

    setIsLoading(true);
    try {
      const configData: any = {
        model: data.model,
        businessContext: data.businessContext || "",
      };
      if (data.apiKey && !data.apiKey.includes("*")) {
        configData.apiKey = data.apiKey;
      }

      const result = configExists
        ? await updateLighthouseConfig(configData)
        : await createLighthouseConfig(configData);

      if (result) {
        setConfigExists(true);
        toast({
          title: "Success",
          description: `Lighthouse AI configuration ${
            configExists ? "updated" : "created"
          } successfully`,
        });
        // Navigate to lighthouse chat page after successful save
        router.push("/lighthouse");
      } else {
        throw new Error("Failed to save configuration");
      }
    } catch (error) {
      toast({
        title: "Error",
        description:
          "Failed to save Lighthouse AI configuration: " + String(error),
        variant: "destructive",
      });
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="rounded-lg border border-gray-200 bg-white p-6 dark:border-gray-800 dark:bg-gray-900">
      <h2 className="mb-4 text-xl font-semibold">Chatbot Settings</h2>
      <p className="mb-6 text-gray-600 dark:text-gray-300">
        Configure your chatbot model and API settings.
      </p>

      <Form {...form}>
        <form
          onSubmit={form.handleSubmit(onSubmit)}
          className="flex flex-col gap-6"
        >
          <div className="flex flex-col gap-6 md:flex-row">
            <div className="md:w-1/3">
              <Controller
                name="model"
                control={form.control}
                render={({ field }) => (
                  <Select
                    label="Model"
                    placeholder="Select a model"
                    labelPlacement="inside"
                    value={field.value}
                    defaultSelectedKeys={[field.value]}
                    onChange={(e) => field.onChange(e.target.value)}
                    variant="bordered"
                    size="md"
                    isRequired
                  >
                    <SelectItem key="gpt-4o-2024-08-06">
                      GPT-4o (Recommended)
                    </SelectItem>
                    <SelectItem key="gpt-4o-mini-2024-07-18">
                      GPT-4o Mini
                    </SelectItem>
                    <SelectItem key="gpt-5-2025-08-07">GPT-5</SelectItem>
                    <SelectItem key="gpt-5-mini-2025-08-07">
                      GPT-5 Mini
                    </SelectItem>
                  </Select>
                )}
              />
            </div>

            <div className="md:flex-1">
              <CustomInput
                control={form.control}
                name="apiKey"
                type="password"
                label="API Key"
                labelPlacement="inside"
                placeholder="Enter your API key"
                variant="bordered"
                isRequired
                isInvalid={!!form.formState.errors.apiKey}
              />
            </div>
          </div>

          <CustomTextarea
            control={form.control}
            name="businessContext"
            label="Business Context"
            labelPlacement="inside"
            placeholder="Enter business context and relevant information for the chatbot (max 1000 characters)"
            variant="bordered"
            minRows={4}
            maxRows={8}
            description={`${form.watch("businessContext")?.length || 0}/1000 characters`}
            isInvalid={!!form.formState.errors.businessContext}
          />

          <div className="flex w-full justify-end">
            <CustomButton
              type="submit"
              ariaLabel="Save Configuration"
              variant="solid"
              color="action"
              size="md"
              isLoading={isLoading}
              startContent={!isLoading && <SaveIcon size={20} />}
            >
              {isLoading ? "Saving..." : "Save"}
            </CustomButton>
          </div>
        </form>
      </Form>
    </div>
  );
};
