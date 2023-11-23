import { Client } from "../utils/index.js";
import { Config } from "../config.js";
import { BuildParamResponse, Receipt, TrustedApp } from "./shared/index.js";

export interface Context {
  config: Config;
  httpOpts: {
    headers: {
      authorization?: string;
      conformance?: string;
    };
  };
  client: Client;
  trustedApp: TrustedApp;
  rtVars: {
    [x: string]: unknown;
  };
  transactionInfo: {
    contract: string;
    method: string;
    build: BuildParamResponse;
    txId?: string;
    receipt?: Receipt;
  };
  token: string;
  oauth2token: string;
}
