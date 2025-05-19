export interface UserAttributes {
  name: string;
  email: string;
  company_name: string;
  date_joined: string;
}

export interface Membership {
  type: string;
  id: string;
}

export interface MembershipMeta {
  count: number;
}

export interface UserRelationships {
  memberships: {
    meta: MembershipMeta;
    data: Membership[];
  };
}

export interface UserData {
  type: string;
  id: string;
  attributes: UserAttributes;
  relationships: UserRelationships;
}

export interface Meta {
  version: string;
}

export interface UserProps {
  data: UserData;
  meta: Meta;
}

export interface TokenAttributes {
  refreshToken: string;
  accessToken: string;
}

export interface TokenData {
  type: string;
  attributes: TokenAttributes;
}

export interface SignInResponse {
  data: TokenData;
}

export interface Role {
  type: "roles";
  id: string;
}

export interface RoleDetail {
  id: string;
  type: "roles";
  attributes: {
    name: string;
    manage_users: boolean;
    manage_account: boolean;
    manage_providers: boolean;
    manage_scans: boolean;
    manage_integrations: boolean;
    unlimited_visibility: boolean;
    permission_state?: string;
    inserted_at?: string;
    updated_at?: string;
    [key: string]: any;
  };
}

export interface MembershipDetailData {
  id: string;
  type: "memberships";
  attributes: {
    role: string;
    date_joined: string;
    [key: string]: any;
  };
  relationships: {
    tenant: {
      data: {
        type: string;
        id: string;
      };
    };
    [key: string]: any;
  };
}

export interface UserDataWithRoles
  extends Omit<UserData, "attributes" | "relationships"> {
  attributes: UserAttributes & {
    role?: {
      name: string;
    };
  };
  relationships: {
    memberships: UserRelationships["memberships"];
    roles?: {
      meta: {
        count: number;
      };
      data: Role[];
    };
  };
}

export interface UserInfoProps {
  user: UserDataWithRoles | null;
  roleDetails?: RoleDetail[];
  membershipDetails?: MembershipDetailData[];
}
