import type { AxiosResponse } from "axios";

export type Alg = "ES256K" | "ES256" | "RS256" | "EdDSA";

export interface TrustedApp {
  privateKey: string;
  name: string;
  kid: string;
  publicKeyPem?: string;
  publicKeyPemBase64?: string;
}

export interface BuildParamResponse {
  info: {
    title: string;
    data: unknown;
  };
  param: {
    [x: string]: unknown;
  };
  method?: string;
}

export interface UnknownObject {
  [x: string]: unknown;
}

export interface ResponseFile extends AxiosResponse {
  headers: {
    "content-disposition": string;
  };
}

export interface ConformanceLog {
  created: number;
  data: {
    request: {
      method: string;
      url: string;
      headers: Record<string, string>;
      body: Record<string, unknown> | string;
    };
    response: {
      statusCode: number;
      headers: Record<string, string>;
      body: Record<string, unknown> | string;
    };
  };
}
