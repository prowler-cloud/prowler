"use client";

import { useEffect, useState } from "react";
import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import { z } from "zod";

import { Button } from "@/components/ui/button";
import {
  Form,
  FormControl,
  FormDescription,
  FormField,
  FormItem,
  FormLabel,
  FormMessage,
} from "@/components/ui/form";
import { Input } from "@/components/ui/input";
import { RadioGroup, RadioGroupItem } from "@/components/ui/radio-group";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { toast } from "@/components/ui/use-toast";
import { 
  createJiraIntegration, 
  updateJiraIntegration, 
  testJiraConnection,
  getJiraProjects,
  getJiraIssueTypes
} from "@/actions/integrations";
import { JiraIntegrationFormType } from "@/types/integrations";

const jiraFormSchema = z.object({
  projectKey: z.string().min(1, "Project key is required"),
  issueType: z.string().min(1, "Issue type is required"),
  authMethod: z.enum(["basic", "oauth2"], {
    required_error: "Authentication method is required",
  }),
  domain: z.string().optional(),
  userEmail: z.string().email().optional(),
  apiToken: z.string().optional(),
  clientId: z.string().optional(),
  clientSecret: z.string().optional(),
  redirectUri: z.string().url().optional(),
}).refine((data) => {
  if (data.authMethod === "basic") {
    return data.domain && data.userEmail && data.apiToken;
  }
  if (data.authMethod === "oauth2") {
    return data.clientId && data.clientSecret && data.redirectUri;
  }
  return true;
}, {
  message: "Required fields for selected authentication method are missing",
});

interface JiraConfigFormProps {
  integration?: {
    id: string;
    config: any;
  };
  providerId?: string;
  onSuccess?: () => void;
  onCancel?: () => void;
}

export function JiraConfigForm({
  integration,
  providerId,
  onSuccess,
  onCancel,
}: JiraConfigFormProps) {
  const [isLoading, setIsLoading] = useState(false);
  const [isTesting, setIsTesting] = useState(false);
  const [projects, setProjects] = useState<{ [key: string]: string }>({});
  const [issueTypes, setIssueTypes] = useState<string[]>([]);
  const [loadingProjects, setLoadingProjects] = useState(false);
  const [loadingIssueTypes, setLoadingIssueTypes] = useState(false);

  const form = useForm<JiraIntegrationFormType>({
    resolver: zodResolver(jiraFormSchema),
    defaultValues: {
      projectKey: integration?.config?.project_key || "",
      issueType: integration?.config?.issue_type || "",
      authMethod: integration?.config?.auth_method || "basic",
      domain: integration?.config?.domain || "",
      userEmail: integration?.config?.user_email || "",
      apiToken: integration?.config?.api_token || "",
      clientId: integration?.config?.client_id || "",
      clientSecret: integration?.config?.client_secret || "",
      redirectUri: integration?.config?.redirect_uri || "",
    },
  });

  const watchedAuthMethod = form.watch("authMethod");
  const watchedCredentials = form.watch([
    "authMethod",
    "domain",
    "userEmail",
    "apiToken",
    "clientId",
    "clientSecret",
    "redirectUri",
  ]);

  // Load projects when credentials change
  useEffect(() => {
    const loadProjects = async () => {
      const formData = form.getValues();
      
      if (formData.authMethod === "basic") {
        if (!formData.domain || !formData.userEmail || !formData.apiToken) {
          return;
        }
      } else if (formData.authMethod === "oauth2") {
        if (!formData.clientId || !formData.clientSecret || !formData.redirectUri) {
          return;
        }
      }

      setLoadingProjects(true);
      try {
        const result = await getJiraProjects({
          authMethod: formData.authMethod,
          domain: formData.domain,
          userEmail: formData.userEmail,
          apiToken: formData.apiToken,
          clientId: formData.clientId,
          clientSecret: formData.clientSecret,
          redirectUri: formData.redirectUri,
        });

        if (result.success && result.data) {
          setProjects(result.data);
        } else {
          toast({
            title: "Error",
            description: result.message || "Failed to load projects",
            variant: "destructive",
          });
        }
      } catch (error) {
        console.error("Error loading projects:", error);
      } finally {
        setLoadingProjects(false);
      }
    };

    loadProjects();
  }, [watchedCredentials, form]);

  // Load issue types when project changes
  useEffect(() => {
    const loadIssueTypes = async () => {
      const formData = form.getValues();
      
      if (!formData.projectKey) {
        return;
      }

      if (formData.authMethod === "basic") {
        if (!formData.domain || !formData.userEmail || !formData.apiToken) {
          return;
        }
      } else if (formData.authMethod === "oauth2") {
        if (!formData.clientId || !formData.clientSecret || !formData.redirectUri) {
          return;
        }
      }

      setLoadingIssueTypes(true);
      try {
        const result = await getJiraIssueTypes({
          projectKey: formData.projectKey,
          authMethod: formData.authMethod,
          domain: formData.domain,
          userEmail: formData.userEmail,
          apiToken: formData.apiToken,
          clientId: formData.clientId,
          clientSecret: formData.clientSecret,
          redirectUri: formData.redirectUri,
        });

        if (result.success && result.data) {
          setIssueTypes(result.data);
        } else {
          toast({
            title: "Error",
            description: result.message || "Failed to load issue types",
            variant: "destructive",
          });
        }
      } catch (error) {
        console.error("Error loading issue types:", error);
      } finally {
        setLoadingIssueTypes(false);
      }
    };

    loadIssueTypes();
  }, [form.watch("projectKey"), watchedCredentials, form]);

  const handleTestConnection = async () => {
    const formData = form.getValues();
    
    setIsTesting(true);
    try {
      const result = await testJiraConnection(formData);
      
      if (result.success) {
        toast({
          title: "Success",
          description: "Connection test successful",
        });
      } else {
        toast({
          title: "Error",
          description: result.message || "Connection test failed",
          variant: "destructive",
        });
      }
    } catch (error) {
      toast({
        title: "Error",
        description: "Failed to test connection",
        variant: "destructive",
      });
    } finally {
      setIsTesting(false);
    }
  };

  const onSubmit = async (data: JiraIntegrationFormType) => {
    setIsLoading(true);
    
    try {
      let result;
      
      if (integration?.id) {
        result = await updateJiraIntegration(integration.id, data);
      } else if (providerId) {
        result = await createJiraIntegration(data, providerId);
      } else {
        throw new Error("Either integration ID or provider ID is required");
      }

      if (result.success) {
        toast({
          title: "Success",
          description: result.message || "Jira integration saved successfully",
        });
        onSuccess?.();
      } else {
        toast({
          title: "Error",
          description: result.message || "Failed to save Jira integration",
          variant: "destructive",
        });
      }
    } catch (error) {
      toast({
        title: "Error",
        description: "Failed to save Jira integration",
        variant: "destructive",
      });
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <Form {...form}>
      <form onSubmit={form.handleSubmit(onSubmit)} className="space-y-6">
        <Card>
          <CardHeader>
            <CardTitle>Authentication Method</CardTitle>
          </CardHeader>
          <CardContent>
            <FormField
              control={form.control}
              name="authMethod"
              render={({ field }) => (
                <FormItem className="space-y-3">
                  <FormControl>
                    <RadioGroup
                      onValueChange={field.onChange}
                      value={field.value}
                      className="flex flex-col space-y-1"
                    >
                      <div className="flex items-center space-x-2">
                        <RadioGroupItem value="basic" id="basic" />
                        <FormLabel htmlFor="basic">Basic Authentication</FormLabel>
                      </div>
                      <div className="flex items-center space-x-2">
                        <RadioGroupItem value="oauth2" id="oauth2" />
                        <FormLabel htmlFor="oauth2">OAuth 2.0</FormLabel>
                      </div>
                    </RadioGroup>
                  </FormControl>
                  <FormMessage />
                </FormItem>
              )}
            />
          </CardContent>
        </Card>

        {watchedAuthMethod === "basic" && (
          <Card>
            <CardHeader>
              <CardTitle>Basic Authentication</CardTitle>
            </CardHeader>
            <CardContent className="space-y-4">
              <FormField
                control={form.control}
                name="domain"
                render={({ field }) => (
                  <FormItem>
                    <FormLabel>Domain</FormLabel>
                    <FormControl>
                      <Input placeholder="your-domain" {...field} />
                    </FormControl>
                    <FormDescription>
                      Your Jira domain (e.g., mycompany for mycompany.atlassian.net)
                    </FormDescription>
                    <FormMessage />
                  </FormItem>
                )}
              />

              <FormField
                control={form.control}
                name="userEmail"
                render={({ field }) => (
                  <FormItem>
                    <FormLabel>User Email</FormLabel>
                    <FormControl>
                      <Input type="email" placeholder="user@example.com" {...field} />
                    </FormControl>
                    <FormDescription>
                      Your Jira user email address
                    </FormDescription>
                    <FormMessage />
                  </FormItem>
                )}
              />

              <FormField
                control={form.control}
                name="apiToken"
                render={({ field }) => (
                  <FormItem>
                    <FormLabel>API Token</FormLabel>
                    <FormControl>
                      <Input type="password" placeholder="••••••••••••••••" {...field} />
                    </FormControl>
                    <FormDescription>
                      Your Jira API token (generate from Atlassian Account Settings)
                    </FormDescription>
                    <FormMessage />
                  </FormItem>
                )}
              />
            </CardContent>
          </Card>
        )}

        {watchedAuthMethod === "oauth2" && (
          <Card>
            <CardHeader>
              <CardTitle>OAuth 2.0 Configuration</CardTitle>
            </CardHeader>
            <CardContent className="space-y-4">
              <FormField
                control={form.control}
                name="clientId"
                render={({ field }) => (
                  <FormItem>
                    <FormLabel>Client ID</FormLabel>
                    <FormControl>
                      <Input placeholder="your-client-id" {...field} />
                    </FormControl>
                    <FormDescription>
                      OAuth 2.0 Client ID from your Jira app
                    </FormDescription>
                    <FormMessage />
                  </FormItem>
                )}
              />

              <FormField
                control={form.control}
                name="clientSecret"
                render={({ field }) => (
                  <FormItem>
                    <FormLabel>Client Secret</FormLabel>
                    <FormControl>
                      <Input type="password" placeholder="••••••••••••••••" {...field} />
                    </FormControl>
                    <FormDescription>
                      OAuth 2.0 Client Secret from your Jira app
                    </FormDescription>
                    <FormMessage />
                  </FormItem>
                )}
              />

              <FormField
                control={form.control}
                name="redirectUri"
                render={({ field }) => (
                  <FormItem>
                    <FormLabel>Redirect URI</FormLabel>
                    <FormControl>
                      <Input placeholder="https://your-app.com/callback" {...field} />
                    </FormControl>
                    <FormDescription>
                      OAuth 2.0 Redirect URI configured in your Jira app
                    </FormDescription>
                    <FormMessage />
                  </FormItem>
                )}
              />
            </CardContent>
          </Card>
        )}

        <Card>
          <CardHeader>
            <CardTitle>Issue Configuration</CardTitle>
          </CardHeader>
          <CardContent className="space-y-4">
            <FormField
              control={form.control}
              name="projectKey"
              render={({ field }) => (
                <FormItem>
                  <FormLabel>Project</FormLabel>
                  <FormControl>
                    <Select 
                      value={field.value} 
                      onValueChange={field.onChange}
                      disabled={loadingProjects}
                    >
                      <SelectTrigger>
                        <SelectValue placeholder={
                          loadingProjects ? "Loading projects..." : "Select a project"
                        } />
                      </SelectTrigger>
                      <SelectContent>
                        {Object.entries(projects).map(([key, name]) => (
                          <SelectItem key={key} value={key}>
                            {key} - {name}
                          </SelectItem>
                        ))}
                      </SelectContent>
                    </Select>
                  </FormControl>
                  <FormDescription>
                    The Jira project where issues will be created
                  </FormDescription>
                  <FormMessage />
                </FormItem>
              )}
            />

            <FormField
              control={form.control}
              name="issueType"
              render={({ field }) => (
                <FormItem>
                  <FormLabel>Issue Type</FormLabel>
                  <FormControl>
                    <Select 
                      value={field.value} 
                      onValueChange={field.onChange}
                      disabled={loadingIssueTypes}
                    >
                      <SelectTrigger>
                        <SelectValue placeholder={
                          loadingIssueTypes ? "Loading issue types..." : "Select an issue type"
                        } />
                      </SelectTrigger>
                      <SelectContent>
                        {issueTypes.map((type) => (
                          <SelectItem key={type} value={type}>
                            {type}
                          </SelectItem>
                        ))}
                      </SelectContent>
                    </Select>
                  </FormControl>
                  <FormDescription>
                    The type of issue to create for security findings
                  </FormDescription>
                  <FormMessage />
                </FormItem>
              )}
            />
          </CardContent>
        </Card>

        <div className="flex justify-between">
          <Button
            type="button"
            variant="outline"
            onClick={handleTestConnection}
            disabled={isTesting}
          >
            {isTesting ? "Testing..." : "Test Connection"}
          </Button>
          
          <div className="flex gap-2">
            {onCancel && (
              <Button type="button" variant="outline" onClick={onCancel}>
                Cancel
              </Button>
            )}
            <Button type="submit" disabled={isLoading}>
              {isLoading ? "Saving..." : integration?.id ? "Update" : "Create"}
            </Button>
          </div>
        </div>
      </form>
    </Form>
  );
}