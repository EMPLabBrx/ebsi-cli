import crypto from "node:crypto";
import { EbsiWallet } from "@cef-ebsi/wallet-lib";
import type { DIDDocument } from "did-resolver";
import { ethers } from "ethers";
import elliptic from "elliptic";
import { base64url } from "multiformats/bases/base64";
import { exportJWK, type JWK, type KeyLike, generateKeyPair } from "jose";
import { Alg } from "../interfaces/index.js";
import { removePrefix0x } from "./utils.js";

const EC = elliptic.ec;

export interface KeyPairJwk {
  id: string;
  kid: string;
  privateKeyJwk: JWK;
  publicKeyJwk: JWK;
  publicKeyEncryptionJwk: JWK;
  privateKeyEncryptionJwk: JWK;
}

export async function generateKeys(alg: string): Promise<{
  publicKeyJwk: JWK;
  privateKeyJwk: JWK;
}> {
  const keys = await generateKeyPair(alg);
  return {
    publicKeyJwk: await exportJWK(keys.publicKey),
    privateKeyJwk: await exportJWK(keys.privateKey),
  };
}

export async function generateKeysEncryption(alg: string): Promise<{
  publicKeyEncryptionJwk: JWK;
  privateKeyEncryptionJwk: JWK;
}> {
  let keys: {
    publicKey: KeyLike | crypto.KeyObject;
    privateKey: KeyLike | crypto.KeyObject;
  };
  if (alg === "EdDSA") {
    keys = crypto.generateKeyPairSync("x25519");
  } else {
    keys = await generateKeyPair(alg);
  }

  return {
    publicKeyEncryptionJwk: await exportJWK(keys.publicKey),
    privateKeyEncryptionJwk: await exportJWK(keys.privateKey),
  };
}

function getPublicKeyJwk(jwk: JWK, alg: string): JWK {
  switch (alg) {
    case "ES256K":
    case "ES256":
    case "EdDSA": {
      const { d, ...publicJwk } = jwk;
      return publicJwk;
    }
    case "RS256": {
      const { d, p, q, dp, dq, qi, ...publicJwk } = jwk;
      return publicJwk;
    }
    default:
      throw new Error(`Algorithm ${alg} not supported`);
  }
}

export function getPrivateKeyJwkES256(privateKeyHex: string): JWK {
  const ec = new EC("p256");
  const privateKey = removePrefix0x(privateKeyHex);
  const keyPair = ec.keyFromPrivate(privateKey, "hex");
  const validation = keyPair.validate();
  if (validation.result === false) {
    throw new Error(validation.reason);
  }
  const pubPoint = keyPair.getPublic();
  return {
    kty: "EC",
    crv: "P-256",
    x: base64url.baseEncode(pubPoint.getX().toBuffer("be", 32)),
    y: base64url.baseEncode(pubPoint.getY().toBuffer("be", 32)),
    d: base64url.baseEncode(Buffer.from(privateKey, "hex")),
  };
}

export function getPrivateKeyJwk(privateKeyHex: string): JWK {
  const publicKeyJWK = new EbsiWallet(privateKeyHex).getPublicKey({
    format: "jwk",
  }) as JWK;
  const d = Buffer.from(removePrefix0x(privateKeyHex), "hex")
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=/g, "");
  return { ...publicKeyJWK, d };
}

export class Client {
  keys: {
    ES256K?: KeyPairJwk;
    ES256?: KeyPairJwk;
    RS256?: KeyPairJwk;
    EdDSA?: KeyPairJwk;
  };

  ethWallet: ethers.Wallet;

  privateKeyHex: string;

  did: string;

  didVersion: number;

  clientId: string;

  accreditationUrl: string;

  proxyId: string;

  issuerState: string;

  constructor() {
    this.keys = {};
  }

  async createRandom(alg: Alg): Promise<void> {
    const { privateKeyJwk } = await generateKeys(alg);
    await this.setJwk(alg, privateKeyJwk);
  }

  async setJwk(alg: Alg, privateKeyJwk: JWK): Promise<void> {
    let privateKeyEncryptionJwk: JWK;
    let publicKeyEncryptionJwk: JWK;
    const publicKeyJwk = getPublicKeyJwk(privateKeyJwk, alg);
    if (alg === "ES256K") {
      privateKeyEncryptionJwk = privateKeyJwk;
      publicKeyEncryptionJwk = publicKeyJwk;
    } else {
      const pair = await generateKeysEncryption(alg);
      privateKeyEncryptionJwk = pair.privateKeyEncryptionJwk;
      publicKeyEncryptionJwk = pair.publicKeyEncryptionJwk;
    }
    this.keys[alg] = {
      id: "",
      kid: "",
      privateKeyJwk,
      publicKeyJwk,
      privateKeyEncryptionJwk,
      publicKeyEncryptionJwk,
    };
  }

  generateDidDocument(): DIDDocument {
    const context = [
      "https://www.w3.org/ns/did/v1",
      "https://w3id.org/security/suites/jws-2020/v1",
    ];
    const didDocument = {
      "@context": context,
      id: this.did,
      verificationMethod: [],
      authentication: [],
      assertionMethod: [],
      capabilityInvocation: [],
    };

    Object.keys(this.keys).forEach((alg) => {
      const key = this.keys[alg] as KeyPairJwk;
      if (!key) return;
      didDocument.verificationMethod.push({
        id: key.kid,
        type: "JsonWebKey2020",
        controller: this.did,
        publicKeyJwk: key.publicKeyJwk,
      });
      didDocument.authentication.push(key.kid);
      didDocument.assertionMethod.push(key.kid);
      didDocument.capabilityInvocation.push(key.kid);
    });

    return didDocument;
  }

  privateKeysBase64(): string {
    const keys = [];
    Object.keys(this.keys).forEach((alg) => {
      const key = this.keys[alg] as KeyPairJwk;
      if (!key) return;
      keys.push({
        type: "JsonWebKey2020",
        id: key.kid,
        alg,
        privateKeyJwk: key.privateKeyJwk,
        publicKeyJwk: key.publicKeyJwk,
        ...(alg === "EdDSA" && {
          privateKeyEncryptionJwk: key.privateKeyEncryptionJwk,
          publicKeyEncryptionJwk: key.publicKeyEncryptionJwk,
        }),
      });
    });
    return Buffer.from(JSON.stringify(keys)).toString("base64");
  }

  toJSON() {
    return {
      keys: this.keys,
      privateKeyHex: this.ethWallet?.privateKey ?? "",
      publicKeyHex: this.ethWallet?.publicKey ?? "",
      address: this.ethWallet?.address ?? "",
      did: this.did,
      didVersion: this.didVersion,
      clientId: this.clientId,
      proxyId: this.proxyId,
      accreditationUrl: this.accreditationUrl,
      issuerState: this.issuerState,
    };
  }
}

export default Client;
