"use client";

import { zodResolver } from "@hookform/resolvers/zod";
import { Select, SelectItem, Spacer } from "@nextui-org/react";
import { SaveIcon } from "lucide-react";
import { useEffect, useState } from "react";
import { Controller, useForm } from "react-hook-form";
import * as z from "zod";

import {
  createAIConfiguration,
  getAIConfiguration,
  updateAIConfiguration,
} from "@/actions/lighthouse";
import { useToast } from "@/components/ui";
import {
  CustomButton,
  CustomInput,
  CustomTextarea,
} from "@/components/ui/custom";
import { Form } from "@/components/ui/form";

const chatbotConfigSchema = z.object({
  model: z.string().nonempty("Model selection is required"),
  apiKey: z.string().nonempty("API Key is required").optional(), // Make optional for initial loading
  businessContext: z
    .string()
    .max(1000, "Business context cannot exceed 1000 characters")
    .optional(),
});

type FormValues = z.infer<typeof chatbotConfigSchema>;

export default function ChatbotConfig() {
  const { toast } = useToast();
  const [isLoading, setIsLoading] = useState(false);
  const [isFetching, setIsFetching] = useState(true);
  const [configExists, setConfigExists] = useState(false);

  // Create form with more lenient validation for initial load
  const form = useForm<FormValues>({
    resolver: zodResolver(chatbotConfigSchema),
    defaultValues: {
      model: "gpt-4o",
      apiKey: "",
      businessContext: "",
    },
    mode: "onChange", // Add this to ensure form updates immediately
  });

  // Add a useEffect to log when form values change
  useEffect(() => {
    const subscription = form.watch((value, { name, type }) => {
      if (name && type) {
        // Only log when we have valid change info
        console.log(
          `Form value changed: ${name} = ${JSON.stringify(value)}, type = ${type}`,
        );
      }
    });

    return () => subscription.unsubscribe();
  }, [form]);

  // Fetch existing configuration using server action
  useEffect(() => {
    let isMounted = true;

    async function loadConfiguration() {
      setIsFetching(true);

      try {
        const response = await getAIConfiguration();

        if (!isMounted) return;

        if (!response) {
          setConfigExists(false);
          return;
        }

        if (response.data?.attributes) {
          setConfigExists(true);
          const attrs = response.data.attributes;
          form.reset({
            model: attrs.model,
            apiKey: attrs.api_key || "",
            businessContext: attrs.business_context || "",
          });

          if (isMounted) {
            toast({
              title: "Configuration Loaded",
              description: `Loaded model: ${attrs.model}`,
            });
          }
        }
      } catch (error) {
        if (isMounted) {
          setConfigExists(false);
          toast({
            title: "Error",
            description: "Failed to load configuration: " + String(error),
            variant: "destructive",
          });
        }
      } finally {
        if (isMounted) {
          setIsFetching(false);
        }
      }
    }

    loadConfiguration();

    return () => {
      isMounted = false; // Cleanup function to flag unmount
    };
  }, []);

  const onSubmit = async (data: FormValues) => {
    if (isLoading) return; // Prevent duplicate submissions
    setIsLoading(true);
    try {
      // Create base config without API key
      const configData: any = {
        model: data.model,
        businessContext: data.businessContext || "",
      };

      // Only include API key if it's provided and doesn't contain asterisks
      if (data.apiKey && !data.apiKey.includes("*")) {
        configData.apiKey = data.apiKey;
      }

      // Conditionally use create or update based on whether configuration exists
      const result = configExists
        ? await updateAIConfiguration(configData)
        : await createAIConfiguration(configData);

      console.log("Operation result:", result);

      if (result) {
        // Set configExists to true after successful creation
        if (!configExists) {
          setConfigExists(true);
        }

        toast({
          title: "Success",
          description: `Chatbot configuration ${configExists ? "updated" : "created"} successfully`,
        });
      } else {
        throw new Error("Failed to save configuration");
      }
    } catch (error) {
      toast({
        title: "Error",
        description: "Failed to save chatbot configuration: " + String(error),
        variant: "destructive",
      });
      console.error(error);
    } finally {
      setIsLoading(false);
    }
  };

  if (isFetching) {
    return (
      <div className="rounded-lg border border-gray-200 bg-white p-6 dark:border-gray-800 dark:bg-gray-900">
        <div className="flex h-40 flex-col items-center justify-center">
          <div className="text-center">
            <p className="text-lg text-gray-600 dark:text-gray-300">
              Loading configuration...
            </p>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="rounded-lg border border-gray-200 bg-white p-6 dark:border-gray-800 dark:bg-gray-900">
      <h2 className="mb-4 text-xl font-semibold">Chatbot Settings</h2>
      <p className="mb-6 text-gray-600 dark:text-gray-300">
        Configure your chatbot model and API settings.
      </p>

      <Form {...form}>
        <form
          onSubmit={form.handleSubmit(onSubmit)}
          className="flex flex-col space-y-6"
        >
          {/* Model Selection */}
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
                <SelectItem key="gpt-4o-2024-08-06" value="gpt-4o-2024-08-06">
                  GPT-4o (Recommended)
                </SelectItem>
                <SelectItem
                  key="gpt-4o-mini-2024-07-18"
                  value="gpt-4o-mini-2024-07-18"
                >
                  GPT-4o Mini
                </SelectItem>
              </Select>
            )}
          />

          <Spacer y={2} />

          {/* API Key Input */}
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

          <Spacer y={2} />

          {/* Business Context Textarea */}
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

          <Spacer y={4} />

          {/* Save Button */}
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
}
