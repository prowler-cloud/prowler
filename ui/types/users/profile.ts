export interface MembershipData {
  type: "memberships";
  id: string;
}

export interface RoleData {
  type: "roles";
  id: string;
}

export interface RoleDetailData {
  id: string;
  type: "roles";
  attributes: {
    name: string;
    manage_users: boolean;
    manage_account: boolean;
    manage_providers: boolean;
    manage_scans: boolean;
    manage_integrations?: boolean;
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

export interface UserDataWithRoles {
  type: "users";
  id: string;
  attributes: {
    name: string;
    email: string;
    company_name: string;
    date_joined: string;
    role?: {
      name: string;
    };
  };
  relationships: {
    memberships: {
      meta: {
        count: number;
      };
      data: MembershipData[];
    };
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
  roleDetails?: RoleDetailData[];
  membershipDetails?: MembershipDetailData[];
}
