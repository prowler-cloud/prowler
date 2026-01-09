"use client";

import { zodResolver } from "@hookform/resolvers/zod";
import { Icon } from "@iconify/react";
import { useEffect, useState } from "react";
import { useForm } from "react-hook-form";
import * as z from "zod";

import {
  getTenantConfig,
  updateTenantConfig,
} from "@/actions/lighthouse/lighthouse";
import { SaveIcon } from "@/components/icons";
import {
  Button,
  Card,
  CardContent,
  CardHeader,
  CardTitle,
} from "@/components/shadcn";
import { useToast } from "@/components/ui";
import { CustomTextarea } from "@/components/ui/custom";
import { Form } from "@/components/ui/form";

const lighthouseSettingsSchema = z.object({
  businessContext: z
    .string()
    .max(1000, "Business context cannot exceed 1000 characters")
    .optional(),
});

type FormValues = z.infer<typeof lighthouseSettingsSchema>;

export const LighthouseSettings = () => {
  const { toast } = useToast();
  const [isLoading, setIsLoading] = useState(false);
  const [isFetchingData, setIsFetchingData] = useState(true);

  const form = useForm<FormValues>({
    resolver: zodResolver(lighthouseSettingsSchema),
    defaultValues: {
      businessContext: "",
    },
    mode: "onChange",
  });

  // Fetch initial data
  useEffect(() => {
    const fetchData = async () => {
      setIsFetchingData(true);
      try {
        // Fetch tenant config
        const configResult = await getTenantConfig();
        if (configResult.data && !configResult.errors) {
          const config = configResult.data.attributes;
          form.reset({
            businessContext: config?.business_context || "",
          });
        }
      } catch (error) {
        console.error("Failed to fetch settings:", error);
      } finally {
        setIsFetchingData(false);
      }
    };

    fetchData();
  }, [form]);

  const onSubmit = async (data: FormValues) => {
    if (isLoading) return;
    setIsLoading(true);
    try {
      const config: Record<string, string> = {
        business_context: data.businessContext || "",
      };

      const result = await updateTenantConfig(config);

      if (result.errors) {
        const errorMessage =
          result.errors[0]?.detail || "Failed to save settings";
        toast({
          title: "Error",
          description: errorMessage,
          variant: "destructive",
        });
      } else {
        toast({
          title: "Success",
          description: "Lighthouse settings saved successfully",
        });
      }
    } catch (error) {
      toast({
        title: "Error",
        description: "Failed to save Lighthouse settings: " + String(error),
        variant: "destructive",
      });
    } finally {
      setIsLoading(false);
    }
  };

  if (isFetchingData) {
    return (
      <Card variant="base" padding="lg">
        <CardHeader>
          <CardTitle>Settings</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="flex items-center justify-center py-12">
            <Icon
              icon="heroicons:arrow-path"
              className="h-8 w-8 animate-spin text-gray-400"
            />
          </div>
        </CardContent>
      </Card>
    );
  }

  return (
    <Card variant="base" padding="lg">
      <CardHeader>
        <CardTitle>Settings</CardTitle>
      </CardHeader>
      <CardContent>
        <Form {...form}>
          <form
            onSubmit={form.handleSubmit(onSubmit)}
            className="flex flex-col gap-6"
          >
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
            />

            <div className="flex w-full justify-end">
              <Button
                type="submit"
                aria-label="Save Settings"
                disabled={isLoading}
              >
                {!isLoading && <SaveIcon size={20} />}
                {isLoading ? "Saving..." : "Save"}
              </Button>
            </div>
          </form>
        </Form>
      </CardContent>
    </Card>
  );
};
