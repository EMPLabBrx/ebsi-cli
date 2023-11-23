import { randomUUID, randomBytes, createHash } from "node:crypto";
import { ethers } from "ethers";
import {
  importJWK,
  SignJWT,
  base64url,
  JWK,
  calculateJwkThumbprint,
} from "jose";
import { util } from "@cef-ebsi/ebsi-did-resolver";
import Joi from "joi";
import { decodeJWT } from "did-jwt";
import {
  Agent as SiopAgent,
  AkeResponse,
  verifyJwtTar,
} from "@cef-ebsi/siop-auth";
import {
  EbsiEnvConfiguration,
  ValidationError,
  verifyCredentialJwt,
} from "@cef-ebsi/verifiable-credential";
import { EbsiWallet } from "@cef-ebsi/wallet-lib";
import {
  formatEthersUnsignedTransaction,
  createVPJwt,
  KeyPairJwk,
  removePrefix0x,
  yellow,
  red,
  computeSchemaId,
  getPublicKeyJwk,
} from "../utils/index.js";
import { Alg, UnknownObject } from "../interfaces/index.js";
import { Context } from "../interfaces/context.js";

export function getUserPin(did: string) {
  return createHash("sha256")
    .update(did)
    .digest()
    .slice(-4)
    .map((byte) => byte % 10)
    .reduce((acc, digit) => `${acc}${digit}`, "");
}

export async function computeVerifyVcJwt(
  inputs: string[],
  context: Context,
  typeApis: string
) {
  const [vcJwt, expectedResult] = inputs;
  let ebsiEnvConfig: EbsiEnvConfiguration = {
    didRegistry: `${context.config.api["did-new"].url}/identifiers`,
    trustedIssuersRegistry: `${context.config.api["tir-new"].url}/issuers`,
    trustedPoliciesRegistry: `${context.config.api["tpr-new"].url}/users`,
  };

  if (typeApis !== "new") {
    ebsiEnvConfig = {
      didRegistry: `${context.config.api.did.url}/identifiers`,
      trustedIssuersRegistry: `${context.config.api.tir.url}/issuers`,
      trustedPoliciesRegistry: `${context.config.api.tpr.url}/users`,
    };
  }

  try {
    await verifyCredentialJwt(vcJwt, {
      ebsiAuthority: context.config.domain.replace(/^https?:\/\//, ""),
      ebsiEnvConfig,
    });
    switch (expectedResult) {
      case "expectRevoked": {
        throw new Error("Credential is not revoked");
      }
      default:
        return "Verifiable Credential is valid";
    }
  } catch (error) {
    if (expectedResult === "expectRevoked") {
      if ((error as Error).message === "Credential is not revoked") throw error;
      if ((error as Error).message.includes("revoked")) {
        return "Verifiable Credential is revoked";
      }
    }
    throw error;
  }
}

export async function compute(
  method: string,
  inputs: (UnknownObject | string)[],
  context: Context
): Promise<unknown> {
  const { config, client } = context;
  switch (method) {
    case "signTransaction": {
      const unsignedTransaction = inputs[0] as unknown as ethers.Transaction;
      const uTx = formatEthersUnsignedTransaction(
        JSON.parse(JSON.stringify(unsignedTransaction)) as ethers.Transaction
      );
      const sgnTx = await client.ethWallet.signTransaction(
        uTx as ethers.Transaction
      );
      yellow(sgnTx);
      return sgnTx;
    }
    case "createPresentationJwt": {
      const verifiableCredential = inputs[0] as string | string[];
      const alg = (inputs[1] as Alg) || "ES256K";
      const audience = inputs[2] as string;
      if (!verifiableCredential)
        throw new Error("Verifiable Credential not defined");
      const { jwtVp, payload } = await createVPJwt(
        client,
        alg,
        verifiableCredential,
        audience,
        config
      );
      yellow({ jwtVp, payload });
      return jwtVp;
    }
    case "createVcJwt": {
      const payloadVc = inputs[0] as {
        id?: string;
        credentialSubject?: {
          id?: string;
        };
        [x: string]: unknown;
      };
      const payloadJwt = inputs[1] as UnknownObject;
      const alg = (inputs[2] || "ES256K") as Alg;
      Joi.assert(
        alg,
        Joi.string().valid("ES256K", "ES256", "RS256", "EdDSA").required()
      );
      if (!client.keys[alg])
        throw new Error(`There is no key defined for alg ${alg}`);
      const privateKey = await importJWK(client.keys[alg].privateKeyJwk, alg);
      const iat = Math.round(Date.now() / 1000);
      const exp = iat + 365 * 24 * 3600;
      const issuanceDate = `${new Date(iat * 1000)
        .toISOString()
        .slice(0, -5)}Z`;
      const expirationDate = `${new Date(exp * 1000)
        .toISOString()
        .slice(0, -5)}Z`;
      const jti = payloadVc.id || `urn:uuid:${randomUUID()}`;
      const sub = payloadVc.credentialSubject?.id;
      const payload = {
        iat,
        jti,
        nbf: iat,
        exp,
        sub,
        vc: {
          "@context": ["https://www.w3.org/2018/credentials/v1"],
          id: jti,
          type: ["VerifiableCredential"],
          issuer: client.did,
          issuanceDate,
          issued: issuanceDate,
          validFrom: issuanceDate,
          expirationDate,
          ...payloadVc,
        },
        ...payloadJwt,
      };
      const vc = await new SignJWT(payload)
        .setProtectedHeader({
          alg,
          typ: "JWT",
          kid: client.keys[alg].kid,
          ...(client.didVersion === 2 && {
            jwk: client.keys[alg].publicKeyJwk,
          }),
        })
        .setIssuer(client.did)
        .sign(privateKey);
      yellow(vc);
      return vc;
    }
    case "signJwt": {
      const [payload, alg, headers] = inputs as [
        UnknownObject,
        Alg,
        UnknownObject
      ];
      const privateKey = await importJWK(client.keys[alg].privateKeyJwk, alg);
      const jwt = await new SignJWT(payload)
        .setProtectedHeader({
          alg,
          typ: "JWT",
          kid: client.keys[alg].kid,
          ...(client.didVersion === 2 && {
            jwk: client.keys[alg].publicKeyJwk,
          }),
          ...headers,
        })
        .sign(privateKey);
      yellow(jwt);
      return jwt;
    }
    case "wait": {
      const [seconds] = inputs as [string];
      const milliseconds = Math.round(Number(seconds) * 1000);
      console.log(`waiting ${milliseconds / 1000} secons`);
      await new Promise((r) => {
        setTimeout(r, milliseconds);
      });
      return 0;
    }
    case "userPin": {
      const [did] = inputs as [string];
      const userPin = getUserPin(did);
      yellow(userPin);
      return userPin;
    }
    case "schemaId": {
      const [schema, base] = inputs as [UnknownObject, "base16" | "base58btc"];
      const schemaId = await computeSchemaId(schema, base);
      yellow(schemaId);
      return schemaId;
    }
    case "checkStatusList2021CredentialSchema": {
      const [credential] = inputs as [UnknownObject];
      try {
        Joi.assert(
          credential,
          Joi.object({
            "@context": Joi.array()
              .ordered(
                Joi.string()
                  .valid("https://www.w3.org/2018/credentials/v1")
                  .required(),
                Joi.string()
                  .valid("https://w3id.org/vc/status-list/2021/v1")
                  .required()
              )
              .items(Joi.string().uri())
              .required(),
            type: Joi.array()
              .ordered(
                // First item must be "VerifiableCredential"
                Joi.string().valid("VerifiableCredential").required()
              )
              .items(
                // "StatusList2021Credential" must be present
                Joi.string().valid("StatusList2021Credential").required(),
                Joi.string()
              )
              .required(),
            credentialSubject: Joi.object({
              id: Joi.string().uri().required(),
              type: Joi.string().valid("StatusList2021").required(),
              statusPurpose: Joi.string()
                .valid("revocation", "suspension")
                .required(),
              encodedList: Joi.string().required(),
            })
              .unknown(true)
              .required(),
          })
            // Allow additional properties
            .unknown(true)
        );
        yellow("StatusList2021 Credential Schema correct");
        return true;
      } catch (error) {
        red(error);
        throw error;
      }
    }
    case "verifyVcJwt-new": {
      try {
        const result = await computeVerifyVcJwt(
          inputs as string[],
          context,
          "new"
        );
        yellow(result);
        return result;
      } catch (error) {
        if (error instanceof ValidationError) {
          red(error.toJSON());
        } else {
          red(error);
        }
        throw error;
      }
    }
    case "verifyVcJwt": {
      try {
        const result = await computeVerifyVcJwt(
          inputs as string[],
          context,
          "new"
        );
        yellow(result);
        return result;
      } catch (error) {
        if (error instanceof ValidationError) {
          red(error.toJSON());
        } else {
          red(error);
        }

        try {
          const result2 = await computeVerifyVcJwt(
            inputs as string[],
            context,
            ""
          );
          yellow(result2);
          return result2;
        } catch (error2) {
          if (error2 instanceof ValidationError) {
            red(error2.toJSON());
          } else {
            red(error2);
          }
          throw error2;
        }
      }
    }
    case "verifyAuthenticationRequest": {
      const request = inputs[0] as {
        client_id: string;
        request: string;
      };
      Joi.assert(
        request,
        Joi.object({
          client_id: Joi.string(),
          request: Joi.string(),
        }).unknown()
      );
      await verifyJwtTar(request.request, {
        trustedAppsRegistry: `${config.api.tar.url}/apps`,
      });
      yellow("Authentication request OK");
      return request.client_id;
    }
    case "verifySessionResponse": {
      const nr = inputs[0] as {
        alg: string;
        nonce: string;
        response: AkeResponse;
      };
      Joi.assert(
        nr,
        Joi.object({
          alg: Joi.string(),
          nonce: Joi.string(),
          response: Joi.object(),
        }).unknown()
      );
      const key = client.keys[nr.alg] as KeyPairJwk;
      if (!key) throw new Error(`There is no key defined for alg ${nr.alg}`);
      const accessToken = await SiopAgent.verifyAkeResponse(nr.response, {
        nonce: nr.nonce,
        privateEncryptionKeyJwk: key.privateKeyEncryptionJwk,
        trustedAppsRegistry: `${config.api.tar.url}/apps`,
        alg: nr.alg,
      });
      yellow(`Session Response OK. Access token: ${accessToken}`);
      return accessToken;
    }
    case "did2": {
      const [jwk] = inputs as [UnknownObject];
      const did = EbsiWallet.createDid("NATURAL_PERSON", jwk);
      yellow(did);
      return did;
    }
    case "sha256": {
      const [dataInput] = inputs as [UnknownObject | string];
      const data =
        typeof dataInput === "object" ? JSON.stringify(dataInput) : dataInput;
      return `0x${createHash("sha256")
        .update(data, "utf8")
        .digest()
        .toString("hex")}`;
    }
    case "decodeJWT": {
      const jwt = inputs[0] as string;
      Joi.assert(jwt, Joi.string());
      const decoded = decodeJWT(jwt) as unknown;
      yellow(decoded);
      return decoded;
    }
    case "decodeBase64": {
      const enc = inputs[0] as string;
      const type = (inputs[1] as string) || "utf8";
      Joi.assert(enc, Joi.string());
      const buffer = Buffer.from(enc, "base64");
      if (type === "buffer") {
        console.log(buffer);
        return buffer;
      }

      const decoded = buffer.toString("utf8");
      yellow(decoded);
      return decoded;
    }
    case "decodeBase64url": {
      const enc = inputs[0] as string;
      Joi.assert(enc, Joi.string());
      const decoded = base64url.decode(enc);
      yellow(decoded);
      return decoded;
    }
    case "decodeHex": {
      const enc = inputs[0] as string;
      Joi.assert(enc, Joi.string());
      const decoded = Buffer.from(removePrefix0x(enc), "hex").toString("utf8");
      yellow(decoded);
      return decoded;
    }
    case "randomID": {
      return randomBytes(32).toString("hex");
    }
    case "subaccountDid": {
      const [did] = inputs as [string];
      Joi.assert(did, Joi.string());
      const subaccountMsiBytes = createHash("sha256")
        .update(did, "utf8")
        .digest()
        .slice(0, 16);
      const subaccount = util.createDid(subaccountMsiBytes);
      yellow(subaccount);
      return subaccount;
    }
    case "statusListIndex": {
      const [did] = inputs as [string];
      Joi.assert(did, Joi.string());
      const statusListIndex = (
        createHash("sha256")
          .update(did, "utf8")
          .digest()
          .slice(0, 6)
          .readUInt32BE() % 131072
      ).toString();
      yellow(statusListIndex);
      return statusListIndex;
    }
    case "thumbprint": {
      const [hexOrJwk] = inputs as [string | UnknownObject];
      let publicKeyJwk: JWK;
      if (typeof hexOrJwk === "string") {
        publicKeyJwk = getPublicKeyJwk(hexOrJwk);
      } else {
        publicKeyJwk = hexOrJwk;
      }
      const thumbprint = await calculateJwkThumbprint(publicKeyJwk, "sha256");
      yellow(thumbprint);
      return thumbprint;
    }
    default:
      red(`Invalid method '${method}'`);
      return 0;
  }
}

export default compute;
