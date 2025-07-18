"use client";

import { useEffect, useState } from "react";
import { Plus } from "lucide-react";

import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from "@/components/ui/dialog";
import { 
  Select, 
  SelectContent, 
  SelectItem, 
  SelectTrigger, 
  SelectValue 
} from "@/components/ui/select";
import { toast } from "@/components/ui/use-toast";
import { JiraConfigForm, JiraIntegrationCard } from "@/components/integrations";
import { auth } from "@/auth.config";
import { Integration, JiraIntegration } from "@/types/integrations";

interface Provider {
  id: string;
  alias: string;
  provider: string;
}

export function IntegrationsContent() {
  const [integrations, setIntegrations] = useState<Integration[]>([]);
  const [providers, setProviders] = useState<Provider[]>([]);
  const [selectedProvider, setSelectedProvider] = useState<string>("");
  const [isAddDialogOpen, setIsAddDialogOpen] = useState(false);
  const [isLoading, setIsLoading] = useState(true);

  const fetchIntegrations = async () => {
    try {
      // This would typically be an API call
      // For now, we'll just set empty state
      setIntegrations([]);
    } catch (error) {
      toast({
        title: "Error",
        description: "Failed to fetch integrations",
        variant: "destructive",
      });
    } finally {
      setIsLoading(false);
    }
  };

  const fetchProviders = async () => {
    try {
      // This would typically be an API call
      // For now, we'll just set empty state
      setProviders([]);
    } catch (error) {
      toast({
        title: "Error",
        description: "Failed to fetch providers",
        variant: "destructive",
      });
    }
  };

  useEffect(() => {
    fetchIntegrations();
    fetchProviders();
  }, []);

  const handleAddSuccess = () => {
    setIsAddDialogOpen(false);
    setSelectedProvider("");
    fetchIntegrations();
  };

  const jiraIntegrations = integrations.filter(
    (integration): integration is JiraIntegration => 
      integration.integration_type === "jira"
  );

  if (isLoading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="text-muted-foreground">Loading integrations...</div>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <div className="flex justify-between items-center">
        <div>
          <h2 className="text-2xl font-bold">Integrations</h2>
          <p className="text-muted-foreground">
            Configure integrations to automatically create tickets from security findings
          </p>
        </div>
        
        <Dialog open={isAddDialogOpen} onOpenChange={setIsAddDialogOpen}>
          <DialogTrigger asChild>
            <Button>
              <Plus className="h-4 w-4 mr-2" />
              Add Integration
            </Button>
          </DialogTrigger>
          <DialogContent className="max-w-2xl max-h-[80vh] overflow-y-auto">
            <DialogHeader>
              <DialogTitle>Add Jira Integration</DialogTitle>
            </DialogHeader>
            
            <div className="space-y-4">
              <div>
                <label className="text-sm font-medium">Provider</label>
                <Select value={selectedProvider} onValueChange={setSelectedProvider}>
                  <SelectTrigger>
                    <SelectValue placeholder="Select a provider" />
                  </SelectTrigger>
                  <SelectContent>
                    {providers.map((provider) => (
                      <SelectItem key={provider.id} value={provider.id}>
                        {provider.alias} ({provider.provider})
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
                {providers.length === 0 && (
                  <p className="text-sm text-muted-foreground mt-2">
                    No providers available. Please add a provider first.
                  </p>
                )}
              </div>

              {selectedProvider && (
                <JiraConfigForm
                  providerId={selectedProvider}
                  onSuccess={handleAddSuccess}
                  onCancel={() => setIsAddDialogOpen(false)}
                />
              )}
            </div>
          </DialogContent>
        </Dialog>
      </div>

      <div className="grid gap-6">
        <div>
          <h3 className="text-lg font-semibold mb-4">Jira Integrations</h3>
          {jiraIntegrations.length > 0 ? (
            <div className="grid gap-4">
              {jiraIntegrations.map((integration) => (
                <JiraIntegrationCard
                  key={integration.id}
                  integration={integration}
                  onUpdate={fetchIntegrations}
                />
              ))}
            </div>
          ) : (
            <div className="text-center py-8 text-muted-foreground">
              <p>No Jira integrations configured</p>
              <p className="text-sm">
                Click "Add Integration" to create your first Jira integration
              </p>
            </div>
          )}
        </div>

        {/* Future integrations can be added here */}
        <div>
          <h3 className="text-lg font-semibold mb-4">Other Integrations</h3>
          <div className="text-center py-8 text-muted-foreground">
            <p>More integrations coming soon...</p>
          </div>
        </div>
      </div>
    </div>
  );
}