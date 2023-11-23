import type { JWK } from "jose";

export interface AuthenticationRequestResponse {
  uri: string;
}

export interface Ake1SigPayload {
  ake1_enc_payload: string;
  ake1_nonce: string;
  did: string;
  iat: number;
  iss: string;
}

export interface AkeResponse {
  ake1_enc_payload: string;
  ake1_sig_payload: Ake1SigPayload;
  ake1_jws_detached: string;
  did?: string;
  kid?: string;
}

export interface AuthorizationObject {
  authorizationId: string;
  resourceApplicationId: string;
  requesterApplicationId: string;
  resourceApplicationName: string;
  requesterApplicationName: string;
  iss: string;
  permissions: {
    create: string;
    read: string;
    update: string;
    delete: string;
  };
  status: string;
  notBefore: number;
  notAfter: number;
}

interface TrustedApp {
  applicationId: string;
  name: string;
  domain: string;
  administrators: string[];
  publicKeys: string[];
  info: {
    [x: string]: unknown;
  };
  authorizations: AuthorizationObject[];
}

export interface TrustedAppResponse {
  data: TrustedApp;
  status: number;
}

export interface JWTHeader {
  alg: string;
  typ: string;
  kid?: string;
}

export interface JWTPayload {
  iss: string;
  sub: string;
  aud: string;
  jti: string;
  exp: number;
  iat: number;
  sub_jwk: JWK | JWK[];
  sub_did_verification_method_uri: string;
  nonce: string;
  claims: {
    [x: string]: unknown;
  };
}
