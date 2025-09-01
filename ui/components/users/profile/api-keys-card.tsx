"use client";

import { Card, CardBody, CardHeader, Input } from "@nextui-org/react";
import { format } from "date-fns";
import { Copy, Eye, Key, Plus, Trash2 } from "lucide-react";
import { useEffect, useState } from "react";

import {
  createAPIKey,
  getRolesForAPIKeys,
  revokeAPIKey,
} from "@/actions/users/api-keys";
import { CustomAlertModal, CustomButton } from "@/components/ui/custom";
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
import { APIKey, RoleDetail } from "@/types/users";

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
  const [showRevokeConfirmation, setShowRevokeConfirmation] = useState(false);
  const [apiKeyToRevoke, setApiKeyToRevoke] = useState<APIKey | null>(null);
  const [newKey, setNewKey] = useState("");
  const [newKeyName, setNewKeyName] = useState("");
  const [keyName, setKeyName] = useState("");
  const [selectedRole, setSelectedRole] = useState<string>("");
  const [expirationOption, setExpirationOption] = useState(1); // Default to "Never"
  const [isDeleting, setIsDeleting] = useState<string | null>(null);
  const [roles, setRoles] = useState<RoleDetail[]>([]);
  const [isLoadingRoles, setIsLoadingRoles] = useState(false);

  // Fetch roles when the dialog opens
  useEffect(() => {
    if (showCreateDialog) {
      setIsLoadingRoles(true);
      getRolesForAPIKeys()
        .then((response) => {
          setRoles(response.data);
        })
        .catch((_error) => {
          toast({
            title: "Error",
            description: "Failed to fetch roles",
            variant: "destructive",
          });
        })
        .finally(() => {
          setIsLoadingRoles(false);
        });
    }
  }, [showCreateDialog]);

  const handleCreateKey = async () => {
    if (!selectedRole) {
      toast({
        title: "Error",
        description: "Please select a role for the API key",
        variant: "destructive",
      });
      return;
    }

    setIsCreating(true);
    try {
      let expiry_date = null;
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
        expiry_date = date.toISOString();
      }

      const response = await createAPIKey({
        name: keyName,
        expiry_date,
        role: selectedRole,
      });
      setNewKey(response.data.attributes.key);
      setNewKeyName(response.data.attributes.name);
      setShowCreateDialog(false);
      setShowKeyDialog(true);
      setKeyName("");
      setSelectedRole("");
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
    setApiKeyToRevoke(apiKey);
    setShowRevokeConfirmation(true);
  };

  const confirmRevokeKey = async () => {
    if (!apiKeyToRevoke) return;

    setIsDeleting(apiKeyToRevoke.id);
    try {
      await revokeAPIKey(apiKeyToRevoke.id);
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
      setShowRevokeConfirmation(false);
      setApiKeyToRevoke(null);
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
                  <Label htmlFor="role">Role</Label>
                  <Select
                    value={selectedRole}
                    onValueChange={(value) => setSelectedRole(value)}
                    disabled={isLoadingRoles}
                  >
                    <SelectTrigger id="role">
                      <SelectValue placeholder="Select a role" />
                    </SelectTrigger>
                    <SelectContent>
                      {isLoadingRoles ? (
                        <SelectItem value="__loading__" disabled>
                          Loading roles...
                        </SelectItem>
                      ) : roles.length === 0 ? (
                        <SelectItem value="__no_roles__" disabled>
                          No roles found.
                        </SelectItem>
                      ) : (
                        roles.map((role) => (
                          <SelectItem key={role.id} value={role.id}>
                            {role.attributes.name}
                          </SelectItem>
                        ))
                      )}
                    </SelectContent>
                  </Select>
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
                  isDisabled={!keyName || isCreating || !selectedRole}
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
                        new Date(apiKey.attributes.created),
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
                      {apiKey.attributes.expiry_date
                        ? format(
                            new Date(apiKey.attributes.expiry_date),
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

      {/* Revoke Confirmation Modal */}
      <CustomAlertModal
        isOpen={showRevokeConfirmation}
        onOpenChange={setShowRevokeConfirmation}
        title="Are you absolutely sure?"
        description={`This action cannot be undone. This will permanently revoke the API key "${apiKeyToRevoke?.attributes.name}" and any applications using it will lose access immediately.`}
      >
        <div className="flex w-full justify-center space-x-6">
          <CustomButton
            type="button"
            ariaLabel="Cancel"
            className="w-full bg-transparent"
            variant="faded"
            size="lg"
            onPress={() => {
              setShowRevokeConfirmation(false);
              setApiKeyToRevoke(null);
            }}
            isDisabled={isDeleting === apiKeyToRevoke?.id}
          >
            Cancel
          </CustomButton>
          <CustomButton
            type="button"
            ariaLabel="Revoke API Key"
            className="w-full"
            variant="solid"
            color="danger"
            size="lg"
            isLoading={isDeleting === apiKeyToRevoke?.id}
            startContent={
              isDeleting !== apiKeyToRevoke?.id && <Trash2 size={20} />
            }
            onPress={confirmRevokeKey}
          >
            {isDeleting === apiKeyToRevoke?.id
              ? "Revoking..."
              : "Revoke API Key"}
          </CustomButton>
        </div>
      </CustomAlertModal>

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
