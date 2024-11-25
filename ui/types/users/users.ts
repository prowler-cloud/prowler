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
