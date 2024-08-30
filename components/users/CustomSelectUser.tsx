import {
  Label,
  Select,
  SelectContent,
  SelectGroup,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui";
import { UserProps } from "@/types";

interface CustomSelectUserProps {
  userData?: UserProps;
}

export const CustomSelectUser: React.FC<CustomSelectUserProps> = ({
  userData,
}) => {
  return (
    <>
      <Label htmlFor="role">
        Select a role<span className="text-red-500">*</span>
      </Label>
      <Select>
        <SelectTrigger className="shadow-none h-12 rounded-xl bg-zinc-100 border-transparent text-foreground-500 focus:ring-2 focus:ring-blue-600 ring-0 hover:bg-zinc-200 focus:border-2 focus:border-white">
          <SelectValue
            placeholder={(userData && userData?.role) || "Select a role"}
          />
        </SelectTrigger>
        <SelectContent className="rounded-xl">
          <SelectGroup className="[&>[data-highlighted]]:bg-transparent">
            <SelectItem value="user">User</SelectItem>
            <SelectItem value="admin">Admin</SelectItem>
          </SelectGroup>
        </SelectContent>
      </Select>
    </>
  );
};
