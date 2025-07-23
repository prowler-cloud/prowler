"use client";

import { Card, CardBody, CardHeader, Input } from "@nextui-org/react";
import { format } from "date-fns";
import { Copy, Eye, Key, Plus, Trash2 } from "lucide-react";
import { useState } from "react";

import { createAPIKey, revokeAPIKey } from "@/actions/users/api-keys";
import { CustomButton } from "@/components/ui/custom";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from "@/components/ui/dialog/dialog";
import { Label } from "@/components/ui/label/Label";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select/Select";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { toast } from "@/components/ui/toast";
import { APIKey } from "@/types/users";

interface APIKeysCardProps {
  apiKeys: APIKey[];
}

const EXPIRATION_OPTIONS = [
  { label: "Never", value: 1 },
  { label: "1 Day", value: 2 },
  { label: "7 Days", value: 3 },
  { label: "30 Days", value: 4 },
  { label: "90 Days", value: 5 },
] as const;

export function APIKeysCard({ apiKeys }: APIKeysCardProps) {
  const [isCreating, setIsCreating] = useState(false);
  const [showCreateDialog, setShowCreateDialog] = useState(false);
  const [showKeyDialog, setShowKeyDialog] = useState(false);
  const [newKey, setNewKey] = useState("");
  const [newKeyName, setNewKeyName] = useState("");
  const [keyName, setKeyName] = useState("");
  const [expirationOption, setExpirationOption] = useState(1); // Default to "Never"
  const [isDeleting, setIsDeleting] = useState<string | null>(null);

  const handleCreateKey = async () => {
    setIsCreating(true);
    try {
      let expires_at = null;
      if (expirationOption !== 1) {
        // Not "Never"
        const date = new Date();
        switch (expirationOption) {
          case 2: // 1 Day
            date.setDate(date.getDate() + 1);
            break;
          case 3: // 7 Days
            date.setDate(date.getDate() + 7);
            break;
          case 4: // 30 Days
            date.setDate(date.getDate() + 30);
            break;
          case 5: // 90 Days
            date.setDate(date.getDate() + 90);
            break;
        }
        expires_at = date.toISOString();
      }

      const response = await createAPIKey({ name: keyName, expires_at });
      setNewKey(response.data.attributes.key);
      setNewKeyName(response.data.attributes.name);
      setShowCreateDialog(false);
      setShowKeyDialog(true);
      setKeyName("");
      setExpirationOption(1); // Reset to "Never"

      toast({
        title: "API Key created",
        description: "Your new API key has been created successfully.",
      });
    } catch (error) {
      toast({
        title: "Error",
        description:
          error instanceof Error ? error.message : "Failed to create API key",
        variant: "destructive",
      });
    } finally {
      setIsCreating(false);
    }
  };

  const handleRevokeKey = async (apiKey: APIKey) => {
    setIsDeleting(apiKey.id);
    try {
      await revokeAPIKey(apiKey.id);
      toast({
        title: "API Key revoked",
        description: "The API key has been revoked successfully.",
      });
    } catch (error) {
      toast({
        title: "Error",
        description:
          error instanceof Error ? error.message : "Failed to revoke API key",
        variant: "destructive",
      });
    } finally {
      setIsDeleting(null);
    }
  };

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text);
    toast({
      title: "Copied",
      description: "API key copied to clipboard.",
    });
  };

  // API now only returns non-revoked keys, so all keys are active
  const activeKeys = apiKeys;

  return (
    <>
      <Card>
        <CardHeader className="flex items-center justify-between dark:bg-prowler-blue-400">
          <div className="flex flex-col gap-1">
            <h4 className="text-lg font-bold">API Keys</h4>
            <p className="text-xs text-gray-500">
              Manage your API keys for programmatic access
            </p>
          </div>
          <Dialog open={showCreateDialog} onOpenChange={setShowCreateDialog}>
            <DialogTrigger asChild>
              <CustomButton ariaLabel="Create API Key" color="action" size="sm">
                <Plus className="mr-2 h-4 w-4" />
                Create API Key
              </CustomButton>
            </DialogTrigger>
            <DialogContent>
              <DialogHeader>
                <DialogTitle>Create API Key</DialogTitle>
                <DialogDescription>
                  Create a new API key for programmatic access to Prowler.
                </DialogDescription>
              </DialogHeader>
              <div className="space-y-4 py-4">
                <div className="space-y-2">
                  <Label htmlFor="key-name">Key Name</Label>
                  <Input
                    id="key-name"
                    placeholder="My API Key"
                    value={keyName}
                    onChange={(e: React.ChangeEvent<HTMLInputElement>) =>
                      setKeyName(e.target.value)
                    }
                  />
                </div>
                <div className="space-y-2">
                  <Label htmlFor="expiration">Expiration</Label>
                  <Select
                    value={expirationOption.toString()}
                    onValueChange={(value) =>
                      setExpirationOption(Number(value))
                    }
                  >
                    <SelectTrigger id="expiration">
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      {EXPIRATION_OPTIONS.map((option) => (
                        <SelectItem
                          key={option.value}
                          value={option.value.toString()}
                        >
                          {option.label}
                        </SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                </div>
              </div>
              <DialogFooter>
                <CustomButton
                  ariaLabel="Cancel"
                  type="button"
                  className="w-full bg-transparent"
                  variant="faded"
                  size="lg"
                  onPress={() => setShowCreateDialog(false)}
                >
                  Cancel
                </CustomButton>
                <CustomButton
                  ariaLabel="Create Key"
                  type="submit"
                  className="w-full"
                  variant="solid"
                  color="action"
                  size="lg"
                  onPress={handleCreateKey}
                  isDisabled={!keyName || isCreating}
                >
                  {isCreating ? "Creating..." : "Create Key"}
                </CustomButton>
              </DialogFooter>
            </DialogContent>
          </Dialog>
        </CardHeader>
        <CardBody className="p-3 dark:bg-prowler-blue-400">
          {activeKeys.length === 0 ? (
            <div className="flex flex-col items-center justify-center py-8 text-center">
              <Key className="text-muted-foreground mb-4 h-12 w-12" />
              <p className="muted-foreground text-sm">
                No API keys found. Create your first API key to get started.
              </p>
            </div>
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Name</TableHead>
                  <TableHead>Prefix</TableHead>
                  <TableHead>Created</TableHead>
                  <TableHead>Last Used</TableHead>
                  <TableHead>Expires</TableHead>
                  <TableHead className="text-right">Actions</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {activeKeys.map((apiKey) => (
                  <TableRow key={apiKey.id}>
                    <TableCell className="font-medium">
                      {apiKey.attributes.name}
                    </TableCell>
                    <TableCell className="font-mono text-sm">
                      {apiKey.attributes.prefix}...
                    </TableCell>
                    <TableCell>
                      {format(
                        new Date(apiKey.attributes.created_at),
                        "MMM d, yyyy",
                      )}
                    </TableCell>
                    <TableCell>
                      {apiKey.attributes.last_used_at
                        ? format(
                            new Date(apiKey.attributes.last_used_at),
                            "MMM d, yyyy",
                          )
                        : "Never"}
                    </TableCell>
                    <TableCell>
                      {apiKey.attributes.expires_at
                        ? format(
                            new Date(apiKey.attributes.expires_at),
                            "MMM d, yyyy",
                          )
                        : "Never"}
                    </TableCell>
                    <TableCell className="text-right">
                      <CustomButton
                        ariaLabel="Revoke API Key"
                        variant="ghost"
                        size="sm"
                        onPress={() => handleRevokeKey(apiKey)}
                        isDisabled={isDeleting === apiKey.id}
                      >
                        <Trash2 className="h-4 w-4" />
                      </CustomButton>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          )}
        </CardBody>
      </Card>

      <Dialog open={showKeyDialog} onOpenChange={setShowKeyDialog}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>API Key Created</DialogTitle>
            <DialogDescription>
              Your API key has been created. This is the only time you&apos;ll
              see this key, so make sure to save it securely.
            </DialogDescription>
          </DialogHeader>
          <div className="space-y-4 py-4">
            <div className="space-y-2">
              <Label>Key Name</Label>
              <p className="muted-foreground text-sm">{newKeyName}</p>
            </div>
            <div className="space-y-2">
              <Label>API Key</Label>
              <div className="flex items-center space-x-2">
                <Input value={newKey} readOnly className="font-mono text-xs" />
                <CustomButton
                  ariaLabel="Copy API Key"
                  size="sm"
                  variant="bordered"
                  className="min-w-unit-8 w-unit-8 h-unit-8 px-0"
                  onPress={() => copyToClipboard(newKey)}
                >
                  <Copy className="h-4 w-4 text-foreground" />
                </CustomButton>
              </div>
            </div>
            <div className="rounded-md bg-yellow-50 p-4 dark:bg-yellow-950">
              <div className="flex">
                <div className="flex-shrink-0">
                  <Eye className="h-5 w-5 text-yellow-400" />
                </div>
                <div className="ml-3">
                  <h3 className="text-sm font-medium text-yellow-800 dark:text-yellow-200">
                    Important
                  </h3>
                  <div className="mt-2 text-sm text-yellow-700 dark:text-yellow-300">
                    <p>
                      This key will not be shown again. Store it in a secure
                      location.
                    </p>
                  </div>
                </div>
              </div>
            </div>
          </div>
          <DialogFooter>
            <CustomButton
              ariaLabel="Done"
              onPress={() => setShowKeyDialog(false)}
            >
              Done
            </CustomButton>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </>
  );
}
