import crypto from "node:crypto";
import Joi from "joi";
import elliptic from "elliptic";
import { base64url } from "multiformats/bases/base64";
import { bases } from "multiformats/basics";
import { JWK } from "jose";
import { AxiosResponse } from "axios";
import $RefParser from "@apidevtools/json-schema-ref-parser";
import canonicalize from "canonicalize";
import { base16 } from "multiformats/bases/base16";
import { base58btc } from "multiformats/bases/base58";
import { ResponseFile, UnknownObject } from "../interfaces/index.js";

const EC = elliptic.ec;

type SerializeInterface = (input: unknown) => string | undefined;
const serialize = canonicalize as unknown as SerializeInterface;

export function prefixWith0x(key: string): string {
  return key.startsWith("0x") ? key : `0x${key}`;
}

export function removePrefix0x(key: string): string {
  return key.startsWith("0x") ? key.slice(2) : key;
}

export function fromHexString(hexString: string): Buffer {
  return Buffer.from(removePrefix0x(hexString), "hex");
}

export function toHexString(bytes: Uint8Array): string {
  return bytes.reduce(
    (str, byte) => str + byte.toString(16).padStart(2, "0"),
    ""
  );
}

export function getPublicKeyJwk(hex: string): JWK {
  const ec = new EC("secp256k1");
  const publicKey = ec
    .keyFromPublic(Buffer.from(hex.replace("0x", ""), "hex"))
    .getPublic();
  return {
    kty: "EC",
    crv: "secp256k1",
    x: base64url.baseEncode(
      Buffer.from(publicKey.getX().toString("hex", 64), "hex")
    ),
    y: base64url.baseEncode(
      Buffer.from(publicKey.getY().toString("hex", 64), "hex")
    ),
  };
}

export function getPublicKeyHex(jwk: JWK): string {
  if (jwk.crv === "secp256k1") {
    const ec = new EC("secp256k1");
    const publicKey = ec.keyFromPublic({
      x: Buffer.from(base64url.baseDecode(jwk.x)).toString("hex"),
      y: Buffer.from(base64url.baseDecode(jwk.y)).toString("hex"),
    });
    return `0x${publicKey.getPublic().encode("hex", false)}`;
  }
  return `0x${Buffer.from(JSON.stringify(jwk)).toString("hex")}`;
}

function removeAnnotations(obj: unknown): unknown {
  /**
   * Lists of annotations keywords:
   * - https://json-schema.org/draft/2020-12/json-schema-validation.html#rfc.section.9
   * - https://json-schema.org/draft/2019-09/json-schema-validation.html#rfc.section.9
   * - https://json-schema.org/draft-07/json-schema-validation.html#rfc.section.10
   */
  const keysToRemove = [
    "title",
    "description",
    "default",
    "deprecated",
    "readOnly",
    "writeOnly",
    "examples",
  ];

  return JSON.parse(
    JSON.stringify(obj, (key, val: unknown) =>
      keysToRemove.includes(key) ? undefined : val
    )
  );
}

export async function computeSchemaId(
  schema: unknown,
  base: "base16" | "base58btc" = "base58btc"
) {
  // 1. Bundle schema
  const bundledSchema = await $RefParser.bundle(schema);

  // 2. Remove annotations
  const sanitizedDocument = removeAnnotations(bundledSchema);

  // 3. Canonicalise
  const canonicalizedDocument = serialize(sanitizedDocument);

  // 4. Compute sha256 of the stringified JSON document
  const hash = crypto
    .createHash("sha256")
    .update(JSON.stringify(canonicalizedDocument), "utf-8")
    .digest();

  // 5. encode hash in base16
  if (base === "base16") {
    return `0x${base16.baseEncode(hash)}`;
  }
  return base58btc.encode(hash);
}

export function isResponseFile(response: AxiosResponse): boolean {
  const resp = response as ResponseFile;
  if (
    resp.headers["content-disposition"] &&
    resp.headers["content-disposition"].includes("attachment; filename=")
  )
    return true;
  return false;
}

export function multibaseEncode(
  base: "base64url" | "base58btc",
  input: Buffer | Uint8Array | string
): string {
  const buffer = typeof input === "string" ? fromHexString(input) : input;
  return bases[base].encode(buffer).toString();
}

export function detachJwt(jwt: string): string {
  const parts = jwt.split(".");
  return `${parts[0]}..${parts[2]}`;
}

export const JoiHash = Joi.string().pattern(/^(0x)?[0-9a-fA-F]{64,64}$/);

export const JoiHexadecimal = Joi.string().pattern(/^(0x)?[0-9a-fA-F]+$/);

export function extractJSONChars(
  str: string,
  chars: string
): {
  json: { [x: string]: unknown };
  start: number;
  end: number;
} {
  const [charIni, charEnd] = chars;
  const start = str.indexOf(` ${charIni}`);
  let end = str.lastIndexOf(charEnd) + 1;
  if (start < 0 || end === 0) return null;
  while (end > start + 1) {
    const candidate = str.substring(start, end);
    try {
      return {
        json: JSON.parse(candidate) as UnknownObject,
        start,
        end,
      };
    } catch (e) {
      // empty
    }
    end = str.substr(0, end - 1).lastIndexOf(charEnd) + 1;
  }
  throw new Error("JSON can not be parsed");
}

export function extractJSON(str: string): {
  json: { [x: string]: unknown };
  start: number;
  end: number;
} {
  const ini1 = str.indexOf("{");
  const ini2 = str.indexOf("[");
  if (ini1 < 0) return extractJSONChars(str, "[]");
  if (ini2 < 0) return extractJSONChars(str, "{}");
  if (ini1 < ini2) return extractJSONChars(str, "{}");
  return extractJSONChars(str, "[]");
}

export function getWords(str: string): {
  words: string[];
  hasComments: boolean;
} {
  const preWords = str.split(" ").filter((word) => word !== "");
  let hasComments = false;
  const words = [];
  preWords.forEach((word) => {
    if (word.startsWith("#")) hasComments = true;
    if (!hasComments) words.push(word);
  });
  return { words, hasComments };
}

export function parseLine(s: string): (string | UnknownObject)[] {
  const parts = [] as (string | UnknownObject)[];
  let str = s;
  // eslint-disable-next-line no-constant-condition
  while (true) {
    const resJson = extractJSON(str);
    const strAux = resJson ? str.substring(0, resJson.start) : str;
    const resWords = getWords(strAux);
    parts.push(...resWords.words);

    if (!resJson || resWords.hasComments) break;

    parts.push(resJson.json);
    str = str.substring(resJson.end);
  }

  return parts;
}
