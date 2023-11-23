import { UnknownObject } from "../shared/index.js";

export interface PaginatedResponse<T> {
  self: string;
  items: T[];
  total: number;
  pageSize: number;
  links: {
    first: string;
    prev: string;
    next: string;
    last: string;
  };
}

export interface Proof {
  type: string;
  created: string;
  proofPurpose: string;
  verificationMethod: string;
  jws: string;
}

export interface Notification {
  schemaId: string;
  type: string[];
  "@context": string[];
  // "id" is used for Cassandra only
  id?: string;
  from: string;
  to: string;
  issuanceDate: string;
  expirationDate?: string;
  payload: UnknownObject;
  proof: Proof;
}

export interface NotificationWithLinks extends Notification {
  _links: {
    self: {
      href: string;
    };
  };
}

export interface DecodedToken {
  aud: string;
  iss: string;
  did: string;
  nonce: string;
  sub: string;
  iat: string;
  exp: string;
}
