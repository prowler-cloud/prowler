"use client";

import { useState } from "react";
import { Settings, Trash2, TestTube } from "lucide-react";

import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { 
  Dialog, 
  DialogContent, 
  DialogHeader, 
  DialogTitle, 
  DialogTrigger 
} from "@/components/ui/dialog";
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
  AlertDialogTrigger,
} from "@/components/ui/alert-dialog";
import { toast } from "@/components/ui/use-toast";
import { JiraConfigForm } from "./forms/jira-config-form";
import { deleteJiraIntegration, testJiraConnection } from "@/actions/integrations";
import { JiraIntegration } from "@/types/integrations";

interface JiraIntegrationCardProps {
  integration: JiraIntegration;
  onUpdate?: () => void;
}

export function JiraIntegrationCard({ integration, onUpdate }: JiraIntegrationCardProps) {
  const [isConfigDialogOpen, setIsConfigDialogOpen] = useState(false);
  const [isDeleting, setIsDeleting] = useState(false);
  const [isTesting, setIsTesting] = useState(false);

  const handleDelete = async () => {
    setIsDeleting(true);
    try {
      const result = await deleteJiraIntegration(integration.id);
      
      if (result.success) {
        toast({
          title: "Success",
          description: "Jira integration deleted successfully",
        });
        onUpdate?.();
      } else {
        toast({
          title: "Error",
          description: result.message || "Failed to delete Jira integration",
          variant: "destructive",
        });
      }
    } catch (error) {
      toast({
        title: "Error",
        description: "Failed to delete Jira integration",
        variant: "destructive",
      });
    } finally {
      setIsDeleting(false);
    }
  };

  const handleTestConnection = async () => {
    setIsTesting(true);
    try {
      const result = await testJiraConnection({
        projectKey: integration.config.project_key,
        issueType: integration.config.issue_type,
        authMethod: integration.config.auth_method,
        domain: integration.config.domain,
        userEmail: integration.config.user_email,
        apiToken: integration.config.api_token,
        clientId: integration.config.client_id,
        clientSecret: integration.config.client_secret,
        redirectUri: integration.config.redirect_uri,
      });
      
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

  const handleConfigSuccess = () => {
    setIsConfigDialogOpen(false);
    onUpdate?.();
  };

  return (
    <Card className="w-full">
      <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
        <CardTitle className="text-lg font-semibold">
          JIRA Integration
        </CardTitle>
        <div className="flex items-center space-x-2">
          <Badge variant={integration.enabled ? "default" : "secondary"}>
            {integration.enabled ? "Enabled" : "Disabled"}
          </Badge>
          {integration.connected !== undefined && (
            <Badge variant={integration.connected ? "default" : "destructive"}>
              {integration.connected ? "Connected" : "Disconnected"}
            </Badge>
          )}
        </div>
      </CardHeader>
      
      <CardContent className="space-y-4">
        <div className="grid grid-cols-2 gap-4 text-sm">
          <div>
            <p className="font-medium text-muted-foreground">Project</p>
            <p>{integration.config.project_key}</p>
          </div>
          <div>
            <p className="font-medium text-muted-foreground">Issue Type</p>
            <p>{integration.config.issue_type}</p>
          </div>
          <div>
            <p className="font-medium text-muted-foreground">Auth Method</p>
            <p className="capitalize">{integration.config.auth_method}</p>
          </div>
          {integration.config.domain && (
            <div>
              <p className="font-medium text-muted-foreground">Domain</p>
              <p>{integration.config.domain}</p>
            </div>
          )}
        </div>

        <div className="flex justify-between items-center pt-4">
          <div className="flex space-x-2">
            <Button
              variant="outline"
              size="sm"
              onClick={handleTestConnection}
              disabled={isTesting}
            >
              <TestTube className="h-4 w-4 mr-2" />
              {isTesting ? "Testing..." : "Test"}
            </Button>
          </div>
          
          <div className="flex space-x-2">
            <Dialog open={isConfigDialogOpen} onOpenChange={setIsConfigDialogOpen}>
              <DialogTrigger asChild>
                <Button variant="outline" size="sm">
                  <Settings className="h-4 w-4 mr-2" />
                  Configure
                </Button>
              </DialogTrigger>
              <DialogContent className="max-w-2xl max-h-[80vh] overflow-y-auto">
                <DialogHeader>
                  <DialogTitle>Configure Jira Integration</DialogTitle>
                </DialogHeader>
                <JiraConfigForm
                  integration={integration}
                  onSuccess={handleConfigSuccess}
                  onCancel={() => setIsConfigDialogOpen(false)}
                />
              </DialogContent>
            </Dialog>

            <AlertDialog>
              <AlertDialogTrigger asChild>
                <Button variant="destructive" size="sm" disabled={isDeleting}>
                  <Trash2 className="h-4 w-4 mr-2" />
                  {isDeleting ? "Deleting..." : "Delete"}
                </Button>
              </AlertDialogTrigger>
              <AlertDialogContent>
                <AlertDialogHeader>
                  <AlertDialogTitle>Are you sure?</AlertDialogTitle>
                  <AlertDialogDescription>
                    This action cannot be undone. This will permanently delete the
                    Jira integration configuration.
                  </AlertDialogDescription>
                </AlertDialogHeader>
                <AlertDialogFooter>
                  <AlertDialogCancel>Cancel</AlertDialogCancel>
                  <AlertDialogAction onClick={handleDelete}>
                    Delete
                  </AlertDialogAction>
                </AlertDialogFooter>
              </AlertDialogContent>
            </AlertDialog>
          </div>
        </div>
      </CardContent>
    </Card>
  );
}