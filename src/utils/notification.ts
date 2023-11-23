import { importJWK, SignJWT } from "jose";
import { detachJwt } from "./utils.js";
import { Alg, Notification, UnknownObject } from "../interfaces/index.js";
import { Client } from "./Client.js";

export async function createNotification(
  client: Client,
  to: string,
  payload: UnknownObject,
  type: string
): Promise<Notification> {
  const ttl = 3600;
  const now = Date.now();
  let alg: Alg;
  if (client.keys.ES256K) alg = "ES256K";
  else if (client.keys.ES256) alg = "ES256";
  else if (client.keys.RS256) alg = "RS256";
  else if (client.keys.EdDSA) alg = "EdDSA";
  else throw new Error("no user defined");

  if (!client.keys[alg])
    throw new Error(`There is no key defined for alg ${alg}`);
  const privateKey = await importJWK(client.keys[alg].privateKeyJwk, alg);
  const jwt = await new SignJWT(payload)
    .setProtectedHeader({
      alg,
      typ: "JWT",
      kid: client.keys[alg].kid,
    })
    .setIssuer(client.did)
    .sign(privateKey);

  return {
    schemaId: "notifications-001",
    type: ["Notification", type],
    "@context": [
      "https://www.w3.org/2018/credentials/v1",
      "https://essif.europa.eu/schemas/vc/2020/v1",
      "https://essif.europa.eu/schemas/notifications/2020/v1",
    ],
    from: client.did,
    to,
    issuanceDate: new Date(now).toISOString(),
    expirationDate: new Date(now + ttl * 1000).toISOString(),
    payload,
    proof: {
      type: "EcdsaSecp256k1Signature2019", // TODO: update
      created: new Date(now).toISOString(),
      proofPurpose: "assertionMethod",
      verificationMethod: client.keys[alg].kid,
      jws: detachJwt(jwt),
    },
  };
}

export default createNotification;
