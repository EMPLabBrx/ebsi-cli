import { randomUUID } from "node:crypto";
import {
  EbsiIssuer,
  EbsiVerifiablePresentation,
  createVerifiablePresentationJwt,
} from "@cef-ebsi/verifiable-presentation";
import { Config } from "../config.js";
import { Client } from "./Client.js";
import { Alg } from "../interfaces/index.js";

export async function createVPJwt(
  client: Client,
  alg: Alg,
  vc: string | string[],
  audience: string,
  config: Config
): Promise<{ jwtVp: string; payload: { [x: string]: unknown } }> {
  const keys = client.keys[alg];
  if (!keys) throw new Error(`No keys defined for alg ${alg}`);

  const issuer: EbsiIssuer = {
    did: client.did,
    kid: keys.kid,
    privateKeyJwk: keys.privateKeyJwk,
    publicKeyJwk: keys.publicKeyJwk,
    alg: alg as "ES256K",
  };

  let verifiableCredential: string[];
  if (vc === "empty") {
    verifiableCredential = [];
  } else if (Array.isArray(vc)) {
    verifiableCredential = vc;
  } else {
    verifiableCredential = [vc];
  }

  const payload = {
    id: `urn:did:${randomUUID()}`,
    "@context": ["https://www.w3.org/2018/credentials/v1"],
    type: ["VerifiablePresentation"],
    holder: client.did,
    verifiableCredential,
  } as EbsiVerifiablePresentation;

  const jwtVp = await createVerifiablePresentationJwt(
    payload,
    issuer,
    audience,
    {
      skipValidation: true,
      ebsiAuthority: config.domain
        .replace("http://", "")
        .replace("https://", ""),
      nonce: randomUUID(),
      exp: Math.floor(Date.now() / 1000) + 900,
      nbf: Math.floor(Date.now() / 1000) - 100,
    }
  );
  return { jwtVp, payload };
}

export default createVPJwt;
