export const USER_SIGN_IN_METHOD = {
  EMAIL_PASSWORD: "email_password",
  GOOGLE: "google",
  GITHUB: "github",
  SAML: "saml",
  PARTNER_SSO: "partner_sso",
} as const;

export type UserSignInMethodType =
  (typeof USER_SIGN_IN_METHOD)[keyof typeof USER_SIGN_IN_METHOD];

type NonSamlUserSignInMethodType = Exclude<
  UserSignInMethodType,
  typeof USER_SIGN_IN_METHOD.SAML
>;

export type UserSignInMethod =
  | {
      method: typeof USER_SIGN_IN_METHOD.SAML;
      domain?: string;
    }
  | {
      method: NonSamlUserSignInMethodType;
      domain?: never;
    };

export interface UserAttributes {
  name: string;
  email: string;
  company_name: string;
  date_joined: string;
}

export interface MembershipData {
  type: string;
  id: string;
}

export interface MembershipMeta {
  count: number;
}

export interface UserRelationships {
  memberships: {
    meta: MembershipMeta;
    data: MembershipData[];
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

export interface RoleData {
  type: "roles";
  id: string;
}

export const PERMISSION_KEY = {
  MANAGE_USERS: "manage_users",
  MANAGE_ACCOUNT: "manage_account",
  MANAGE_PROVIDERS: "manage_providers",
  MANAGE_SCANS: "manage_scans",
  MANAGE_INTEGRATIONS: "manage_integrations",
  MANAGE_BILLING: "manage_billing",
  MANAGE_ALERTS: "manage_alerts",
  MANAGE_LIGHTHOUSE_AI_CONFIGURATION: "manage_lighthouse_ai_configuration",
  UNLIMITED_VISIBILITY: "unlimited_visibility",
} as const;

export type PermissionKey =
  (typeof PERMISSION_KEY)[keyof typeof PERMISSION_KEY];

export type RolePermissionAttributes = Pick<
  RoleDetail["attributes"],
  PermissionKey
>;

export const TENANT_MEMBERSHIP_ROLE = {
  Owner: "owner",
  Member: "member",
} as const;

export type TenantMembershipRole =
  (typeof TENANT_MEMBERSHIP_ROLE)[keyof typeof TENANT_MEMBERSHIP_ROLE];

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
    manage_billing?: boolean;
    manage_alerts?: boolean;
    manage_lighthouse_ai_configuration?: boolean;
    unlimited_visibility: boolean;
    permission_state?: string;
    inserted_at?: string;
    updated_at?: string;
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
      data: RoleData[];
    };
  };
}

export interface UserInfoProps {
  user: UserDataWithRoles | null;
  roleDetails?: RoleDetail[];
  membershipDetails?: MembershipDetailData[];
}

export interface TenantDetailData {
  type: string;
  id: string;
  attributes: {
    name: string;
  };
  relationships: {
    memberships: {
      meta: {
        count: number;
      };
      data: Array<{
        type: string;
        id: string;
      }>;
    };
  };
}

export interface TenantOption {
  id: string;
  name: string;
}

export type IncludedItem = RoleDetail | MembershipDetailData | TenantDetailData;

export interface UserProfileResponse {
  data: UserDataWithRoles;
  included?: IncludedItem[];
  meta?: {
    version: string;
  };
}
