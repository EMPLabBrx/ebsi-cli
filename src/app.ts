/* eslint-disable no-use-before-define, @typescript-eslint/no-use-before-define */
import { randomBytes, randomUUID } from "node:crypto";
import { URL, URLSearchParams } from "node:url";
import { ethers } from "ethers";
import chalk from "chalk";
import qs from "qs";
import { EbsiWallet } from "@cef-ebsi/wallet-lib";
import { QueryOptions } from "cassandra-driver";
import lodashSet from "lodash.set";
import {
  calculateJwkThumbprint,
  importJWK,
  JWK,
  SignJWT,
  base64url,
} from "jose";
import fs, { createWriteStream } from "fs";
import Joi from "joi";
import { Agent as SiopAgent, AkeResponse } from "@cef-ebsi/siop-auth";
import readline from "readline";
import { ConfigApi, loadConfig, SupportedEnvs } from "./config.js";
import * as utils from "./utils/index.js";
import { buildParam } from "./buildParam/index.js";
import {
  BuildParamResponse,
  ResponseFile,
  JsonRpcResponse,
  Receipt,
  TrustedApp,
  UnknownObject,
  Alg,
  ConformanceLog,
} from "./interfaces/shared/index.js";
import {
  isResponseFile,
  jsonrpcBody,
  paramSignedTransaction,
  parseLine,
  prefixWith0x,
  getPrivateKeyHex,
} from "./utils/index.js";
import { Client, getPrivateKeyJwk } from "./utils/Client.js";
import {
  authorisationV3,
  authorisationV4,
  compute,
  view,
  conformanceV3,
  conformanceV4,
  ledgerV4,
  ledgerV3,
  waitToBeMined,
} from "./commands/index.js";

let config = loadConfig();

if (!fs.existsSync("./downloads")) {
  fs.mkdirSync("./downloads");
}

let client = new Client();

let transactionInfo: {
  contract: string;
  method: string;
  build: BuildParamResponse;
  txId?: string;
  receipt?: Receipt;
};
let trustedApp: TrustedApp;
let token: string;
let oauth2token: string;
let httpOpts: {
  headers: {
    authorization?: string;
    conformance?: string;
  };
} = {
  headers: {},
};
let httpOptsUrlencoded: {
  headers: {
    authorization?: string;
    conformance?: string;
    "content-type"?: "application/x-www-form-urlencoded";
  };
} = {
  headers: {},
};
const rtVars: {
  [x: string]: unknown;
} = {}; // runtime variables

const algSchema = Joi.string()
  .valid("ES256K", "ES256", "RS256", "EdDSA")
  .required();

async function setVar(key: string, value: unknown, printVar = true) {
  lodashSet(rtVars, key, value);
  if (key.startsWith("user.")) {
    await execCommand("using user user");
    return;
  }
  if (!printVar) return;
  utils.cyanBold(`Value saved in '${key}':`);
  utils.cyan(value);
}

function updateHttpOpts() {
  const conformanceId = readValue<string | undefined>("conformanceId", true);
  httpOpts = {
    headers: {
      ...((token || oauth2token) && {
        authorization: `Bearer ${token || oauth2token}`,
      }),
      ...(conformanceId && { conformance: conformanceId }),
    },
  };
  httpOptsUrlencoded = {
    headers: {
      ...((token || oauth2token) && {
        authorization: `Bearer ${token || oauth2token}`,
      }),
      ...(conformanceId && { conformance: conformanceId }),
      "content-type": "application/x-www-form-urlencoded",
    },
  };
}

function readValue<T = unknown>(input: unknown, required = false): T {
  if (!input || typeof input !== "string") return input as T;
  const parts = input.split(".");
  let fieldName = parts[0];
  if (typeof rtVars[fieldName] === "undefined") {
    if (required) return undefined;
    return input as T;
  }
  let i = 0;
  let obj = rtVars;
  while (i < parts.length - 1) {
    obj = obj[fieldName] as UnknownObject;
    i += 1;
    fieldName = parts[i];
  }
  return obj[fieldName] as T;
}

function urlPath(inputs: unknown[]): string {
  return inputs.map((input) => readValue(input)).join("");
}

async function using(
  method: string,
  ...params: (string | UnknownObject)[]
): Promise<unknown> {
  switch (method) {
    case "token": {
      token = params[0] === "empty" ? null : readValue<string>(params[0]);
      updateHttpOpts();
      utils.yellow(token);
      return 0;
    }
    case "oauth2token": {
      oauth2token = params[0] === "empty" ? null : readValue<string>(params[0]);
      updateHttpOpts();
      utils.yellow(oauth2token);
      return 0;
    }
    case "user": {
      const existingUser = readValue<Client | string>(params[0]);
      if (existingUser && typeof existingUser !== "string") {
        // load the existing user
        client = new Client();
        client.did = existingUser.did;
        client.didVersion = existingUser.didVersion;
        client.privateKeyHex = existingUser.privateKeyHex;
        client.clientId = existingUser.clientId;
        client.accreditationUrl = existingUser.accreditationUrl;
        client.proxyId = existingUser.proxyId;
        client.issuerState = existingUser.issuerState;
        if (existingUser.privateKeyHex) {
          client.ethWallet = new ethers.Wallet(existingUser.privateKeyHex);
        }
        client.keys = existingUser.keys;
        await setVar("user", client.toJSON(), false);
        await execCommand("view user", false);
        return client;
      }

      if (params[0] === "null") {
        client = new Client();
        await setVar("user", client.toJSON(), false);
        utils.yellow("User removed");
        return 0;
      }
      const alg = readValue<Alg>(params[0]) || "ES256K";
      const didMethod = readValue<string>(params[1]) || "did1";
      const privateKey = readValue<JWK | string>(params[2]);
      client.did = readValue<string>(params[3]) || client.did;
      let verificationMethodId = readValue<string>(params[4]);
      Joi.assert(alg, algSchema);

      if (client.keys[alg] && !privateKey) {
        throw new Error(
          [
            `Private key can not be generated randomly for alg '${alg}' `,
            "because it is already defined. If you want to update it ",
            "set a specific private key. If you want to create a new ",
            "random user remove the existing one first with the command ",
            "'using user null'.",
          ].join("")
        );
      }

      if (alg === "ES256K") {
        if (!privateKey) {
          client.ethWallet = ethers.Wallet.createRandom();
        } else if (typeof privateKey === "string") {
          client.ethWallet = new ethers.Wallet(prefixWith0x(privateKey));
        } else {
          client.ethWallet = new ethers.Wallet(getPrivateKeyHex(privateKey));
        }
        client.privateKeyHex = client.ethWallet.privateKey;
        const privateKeyJwk = getPrivateKeyJwk(client.ethWallet.privateKey);
        await client.setJwk(alg, privateKeyJwk);
      } else if (alg === "ES256" && typeof privateKey === "string") {
        const privateKeyJwk = utils.getPrivateKeyJwkES256(privateKey);
        await client.setJwk(alg, privateKeyJwk);
      } else {
        const privateKeyJwk = privateKey as JWK;
        if (privateKeyJwk) {
          await client.setJwk(alg, privateKeyJwk);
        } else {
          await client.createRandom(alg);
        }
      }

      switch (didMethod) {
        case "did1": {
          client.didVersion = 1;
          if (!client.did) {
            client.did = EbsiWallet.createDid();
          }
          if (!verificationMethodId) {
            verificationMethodId = await calculateJwkThumbprint(
              client.keys[alg].publicKeyJwk,
              "sha256"
            );
          }
          break;
        }
        case "did2": {
          client.didVersion = 2;
          client.did = EbsiWallet.createDid(
            "NATURAL_PERSON",
            client.keys[alg].publicKeyJwk
          );
          if (!verificationMethodId) {
            verificationMethodId = client.did.slice(8);
          }
          break;
        }
        default:
          throw new Error("did method must be 'did1' or 'did2'");
      }
      client.keys[alg].id = verificationMethodId;
      client.keys[alg].kid = `${client.did}#${verificationMethodId}`;

      await setVar("user", client.toJSON(), false);
      await execCommand("view user", false);
      return client;
    }
    case "ethuser": {
      if (params[0] === "null") {
        client = new Client();
        await setVar("user", client.toJSON(), false);
        utils.yellow("User removed");
        return client;
      }
      await execCommand(`using user ES256K ${params.join(" ")}`, true);
      return client;
    }
    case "app":
    case "app-new": {
      const name = params[0] as string;
      const privateKey = params[1] as string;
      const publicKeyPem = new EbsiWallet(privateKey).getPublicKey({
        format: "pem",
      });
      const publicKeyPemBase64 = Buffer.from(publicKeyPem).toString("base64");
      trustedApp = {
        name,
        privateKey,
        publicKeyPem,
        publicKeyPemBase64,
        kid: `${
          method === "app" ? config.api.tar.url : config.api["tar-new"].url
        }/apps/${name}`,
      };
      utils.yellow(trustedApp);
      return trustedApp;
    }
    default:
      utils.red(`Invalid subject '${method}'`);
      return 0;
  }
}

async function authorisationV2(
  method: string,
  inputs: string[]
): Promise<unknown> {
  const apiUrl = config.api.authorisationV2.url;
  switch (method) {
    case "get": {
      const response = await utils.httpCall.get(
        `${apiUrl}${urlPath(inputs)}`,
        httpOpts
      );
      return response.data as unknown;
    }
    case "siopRequest": {
      return utils.siopRequestV2(config, httpOpts);
    }
    case "siopSession": {
      const callbackUrl = readValue<string>(inputs[0]);
      const alg = readValue<string>(inputs[1]) || "ES256K";
      const verifiedClaims = readValue<string>(inputs[2]);
      Joi.assert(callbackUrl, Joi.string());
      Joi.assert(alg, algSchema);
      Joi.assert(verifiedClaims, Joi.string().optional());
      return utils.siopSessionV2(
        client,
        callbackUrl,
        alg,
        httpOpts,
        verifiedClaims
      );
    }
    case "siop": {
      const alg = readValue<string>(inputs[0]) || "ES256K";
      const vcJwtEOS = readValue<string>(inputs[1]);
      let vpJwt = "";
      if (vcJwtEOS) {
        vpJwt = await execCommand<string>(
          `compute createPresentationJwt ${vcJwtEOS} ${alg} authorisation-api`,
          true
        );
      }

      const request = await execCommand("authorisation-old siopRequest", true);
      const callbackUrl = await execCommand<string>(
        `compute verifyAuthenticationRequest ${JSON.stringify(request)}`,
        true
      );
      const sessionResponse = await execCommand(
        `authorisation-old siopSession ${callbackUrl} ${alg} ${vpJwt}`,
        true
      );
      const accessToken = await execCommand<string>(
        `compute verifySessionResponse ${JSON.stringify(sessionResponse)}`,
        true
      );
      return accessToken;
    }
    case "oauth2":
    case "oauth2Session": {
      return utils.oauth2SessionV2(trustedApp, inputs[0], config);
    }
    default:
      utils.red(`Invalid method '${method}'`);
      break;
  }
  return 0;
}

async function proxydatahub(
  method: string,
  inputs: (string | UnknownObject)[]
): Promise<unknown> {
  const apiUrl = config.api.datahub.url;
  const storageApiUrl = config.api.storage.url;
  switch (method) {
    case "get": {
      Joi.assert(inputs[0], Joi.string());
      const response = await utils.httpCall.get(
        `${apiUrl}${urlPath(inputs)}`,
        httpOpts
      );
      return response.data as unknown;
    }
    case "insert": {
      Joi.assert(inputs[0], Joi.object().optional());
      Joi.assert(inputs[1], Joi.string().optional());
      Joi.assert(inputs[2], Joi.string().optional());
      const data =
        typeof inputs[0] === "object"
          ? base64url.encode(Buffer.from(JSON.stringify(inputs[0])))
          : base64url.encode(randomBytes(20));
      const visibility = (inputs[1] as string) || "private";
      const did = (inputs[2] as string) || "";
      const url = `${apiUrl}/attributes`;
      const body = {
        storageUri: `${storageApiUrl}/stores/distributed`,
        visibility,
        ...(did && { sharedWith: did }),
        did: client.did,
        contentType: "application/ld+json",
        dataLabel: "document",
        data,
        proof: {},
      };
      return utils.httpCall.post(url, body, httpOpts);
    }
    case "patch": {
      Joi.assert(inputs[0], Joi.string());
      Joi.assert(inputs[1], Joi.array().optional());
      const attributeId = inputs[0] as string;
      const patchOps = Array.isArray(inputs[1])
        ? inputs[1]
        : [
            {
              op: "replace",
              path: "/contentType",
              value: "application/ld+json",
            },
          ];
      const url = `${apiUrl}/attributes/${attributeId}`;
      return utils.httpCall.patch(url, patchOps, httpOpts);
    }
    case "delete": {
      Joi.assert(inputs[0], Joi.string());
      const attributeId = inputs[0] as string;
      const url = `${apiUrl}/attributes/${attributeId}`;
      return utils.httpCall.delete(url, httpOpts);
    }
    default:
      utils.red(`Invalid method '${method}'`);
      break;
  }
  return 0;
}

async function notifications(
  method: string,
  ...inputs: (string | UnknownObject)[]
): Promise<unknown> {
  const apiUrl = config.api.notifications.url;
  switch (method) {
    case "get": {
      Joi.assert(inputs[0], Joi.string());
      const response = await utils.httpCall.get(
        `${apiUrl}${urlPath(inputs)}`,
        httpOpts
      );
      return response.data as unknown;
    }
    case "insert": {
      Joi.assert(inputs[0], Joi.string());
      Joi.assert(inputs[1], Joi.object().optional());
      Joi.assert(inputs[2], Joi.string().optional());
      const to = inputs[0] as string;
      const payload =
        typeof inputs[1] === "object"
          ? inputs[1]
          : {
              "@context": "ebsi.eu",
              data: randomBytes(32).toString("hex"),
            };
      const type = (inputs[2] as string) || "StoreVerifiableCredential";

      const url = `${apiUrl}/notifications`;
      const data = await utils.createNotification(client, to, payload, type);
      const response = await utils.httpCall.post(url, data, httpOpts);
      const { location } = response.headers as { location: string };
      const notificationId = location.substring(location.lastIndexOf("/") + 1);
      utils.yellow("Notification Id:");
      utils.yellow(notificationId);
      return response.data as UnknownObject;
    }
    case "delete": {
      Joi.assert(inputs[0], Joi.string());
      Joi.assert(inputs[1], Joi.object().optional());
      if (inputs[0] === "all") {
        const response = await utils.httpCall.get(
          `${apiUrl}/notifications?page[size]=50`,
          httpOpts
        );
        const { items } = response.data as {
          items: {
            type: string[];
            payload: { id: number; status: number };
            _links: { self: { href: string } };
          }[];
        };
        for (let i = 0; i < items.length; i += 1) {
          // eslint-disable-next-line no-underscore-dangle
          const { href } = items[i]._links.self;
          const notificationId = href.substring(href.lastIndexOf("/") + 1);
          const url = `${apiUrl}/notifications/${notificationId}`;
          await utils.httpCall.delete(url, httpOpts);
        }
        return 0;
      }
      const notificationId = inputs[0] as string;
      const url = `${apiUrl}/notifications/${notificationId}`;
      return utils.httpCall.delete(url, httpOpts);
    }
    default:
      utils.red(`Invalid method '${method}'`);
      break;
  }
  return 0;
}

async function storage(method: string, inputs: (string | UnknownObject)[]) {
  const apiUrl = config.api.storage.url;
  switch (method) {
    case "get": {
      Joi.assert(inputs[0], Joi.string());
      const storageUrlPath = urlPath(inputs);
      const isDownloadingFile =
        /stores\/distributed\/files\/0x([a-zA-Z0-9]){64}$/.exec(storageUrlPath);
      if (!isDownloadingFile) {
        const response = await utils.httpCall.get(
          `${apiUrl}${storageUrlPath}`,
          httpOpts
        );
        return response.data as unknown;
      }

      const response = await utils.httpCall.get(`${apiUrl}${storageUrlPath}`, {
        ...httpOpts,
        responseType: "stream",
      });

      let filename: string;
      if (isResponseFile(response)) {
        filename = (response as ResponseFile).headers[
          "content-disposition"
        ].replace("attachment; filename=", "");
      } else {
        filename = `error-${randomBytes(12).toString("hex")}.txt`;
      }
      const filepath = `./downloads/${filename}`;
      const writer = createWriteStream(filepath);

      await new Promise((resolve, reject) => {
        (response.data as { pipe: (w: fs.WriteStream) => void }).pipe(writer);
        let error = null;
        writer.on("error", (err) => {
          error = err;
          writer.close();
          reject(err);
        });
        writer.on("close", () => {
          if (!error) {
            resolve(true);
          }
        });
      });

      if (!isResponseFile(response)) {
        // there is an error
        const dataString = fs.readFileSync(filepath, "utf8");
        fs.unlinkSync(filepath);
        try {
          const jsonData = JSON.parse(dataString) as UnknownObject;
          utils.red(jsonData);
        } catch (e) {
          utils.red(dataString);
        }
        throw new Error(
          `Requests failed with status code ${response.status}: ${dataString}`
        );
      }

      utils.green(`Binary data: ${filename}`);
      return 0;
    }
    case "file": {
      Joi.assert(inputs[0], Joi.string());
      const methodFile = inputs[0] as string;
      return utils.fileController(
        httpOpts,
        apiUrl,
        methodFile,
        inputs.slice(1)
      );
    }
    case "keyvalue": {
      Joi.assert(inputs[0], Joi.string());
      const methodKeyValue = inputs[0] as string;
      return utils.keyValueController(
        httpOpts,
        apiUrl,
        methodKeyValue,
        inputs.slice(1)
      );
    }
    case "jsonrpc": {
      Joi.assert(inputs[0], Joi.array());
      return utils.jsonrpcStorage(
        httpOpts,
        apiUrl,
        inputs[0] as unknown as UnknownObject[]
      );
    }
    default:
      utils.red(`Invalid method '${method}'`);
      break;
  }
  return 0;
}

async function cassandra(method: string, inputs: (string | UnknownObject)[]) {
  switch (method) {
    case "query": {
      Joi.assert(inputs[0], Joi.array().items(Joi.string()));
      const [query, ...params] = inputs[0] as unknown as string[];
      const options: QueryOptions = {
        consistency: query.trim().startsWith("select")
          ? config.cassandra.consistency.read
          : config.cassandra.consistency.write,
        prepare: true,
      };
      if (params.length > 0 && typeof params[params.length - 1] === "object") {
        Object.assign(options, params.pop());
      }
      const { rows, pageState } = await config.cassandra.client.execute(
        query,
        params,
        options
      );
      return {
        rows,
        pageState,
      };
    }
    default:
      utils.red(`Invalid method '${method}'`);
      break;
  }
  return 0;
}

async function onboarding(
  method: string,
  ...params: string[]
): Promise<unknown> {
  const apiUrl = config.api.onboarding.url;
  switch (method) {
    case "get": {
      const response = await utils.httpCall.get(
        `${apiUrl}${urlPath(params)}`,
        httpOpts
      );
      return response.data as unknown;
    }
    case "session": {
      return utils.httpCall.post(
        `${apiUrl}/sessions`,
        {
          onboarding: "eu-login",
          info: {
            "eul-ticket": readValue(params[0]),
          },
        },
        httpOpts
      );
    }
    case "authenticationRequests": {
      const response = await utils.httpCall.post(
        `${apiUrl}/authentication-requests`,
        {
          scope: "ebsi users onboarding",
        },
        httpOpts
      );
      return response.data;
    }
    case "sendAuthResponse": {
      const alg = readValue<Alg>(params[0]) || "ES256K";
      Joi.assert(alg, algSchema);
      const nonce = randomUUID();

      const key = client.keys[alg];
      if (!key) throw new Error(`There is no key defined for alg ${alg}`);
      const callbackUrl = `${apiUrl}/authentication-responses`;

      const agent = new SiopAgent({
        privateKey: await importJWK(key.privateKeyJwk, alg),
        alg,
        kid: key.kid,
        siopV2: true,
      });

      const { idToken } = await agent.createResponse(
        {
          nonce,
          redirectUri: callbackUrl,
          claims: {
            encryption_key: key.publicKeyEncryptionJwk,
          },
          responseMode: "form_post",
        },
        {
          syntaxType:
            client.didVersion === 1 ? "jwk_thumbprint_subject" : "did_subject",
        }
      );

      const data = `id_token=${idToken}`;
      const response = await utils.httpCall.post<{
        verifiableCredential: string;
      }>(callbackUrl, data, {
        headers: {
          ...httpOpts.headers,
          "content-type": "application/x-www-form-urlencoded",
        },
      });
      return response.data.verifiableCredential;
    }
    case "authentication": {
      const alg = params[0] || "ES256K";
      const vc: string | UnknownObject = await execCommand(
        `onboarding sendAuthResponse ${alg}`,
        true
      );
      const vp = await execCommand<string>(
        `compute createPresentationJwt ${
          vc as string
        } ${alg} authorisation-api`,
        true
      );

      const request = await execCommand<{ [x: string]: unknown }>(
        `authorisation-old siopRequest`,
        true
      );
      const callbackUrl = await execCommand<string>(
        `compute verifyAuthenticationRequest ${JSON.stringify(request)}`,
        true
      );
      const sessionResponse = await execCommand<AkeResponse>(
        `authorisation-old siopSession ${callbackUrl} ${alg} ${vp}`,
        true
      );
      const accessToken = await execCommand<string>(
        `compute verifySessionResponse ${JSON.stringify(sessionResponse)}`,
        true
      );
      return accessToken;
    }
    default:
      utils.red(`Invalid method '${method}'`);
      break;
  }
  return 0;
}

async function conformanceOld(
  method: string,
  inputs: (UnknownObject | string)[]
): Promise<unknown> {
  const apiUrl = config.api.conformanceV2.url;
  switch (method) {
    case "get": {
      const response = await utils.httpCall.get(
        `${apiUrl}${urlPath(inputs)}`,
        httpOpts
      );
      return response.data as unknown;
    }
    case "setId": {
      const id = readValue<string>(inputs[0]);
      let conformanceId;
      if (id === "null") conformanceId = undefined;
      else if (!id) conformanceId = randomUUID();
      else conformanceId = id;
      await setVar("conformanceId", conformanceId);
      updateHttpOpts();
      return execCommand("view conformanceId", false);
    }
    case "issuerInitiate": {
      const flowType = readValue<string>(inputs[0]) || "same-device";
      const redirect = readValue<string>(inputs[1]) || "false";

      const urlParams = { redirect, flow_type: flowType };
      const response = await utils.httpCall.get(
        `${apiUrl}/issuer-mock/initiate?${qs.stringify(urlParams)}`,
        httpOpts
      );
      const openid = response.data as string;
      return qs.parse(openid.split("?")[1]);
    }
    case "issuerAuthorize": {
      const redirectUri =
        readValue<string>(inputs[0]) || "http://localhost:3000";
      const credentialType = readValue<string>(inputs[1]);
      Joi.assert(redirectUri, Joi.string());
      Joi.assert(credentialType, Joi.string().optional());

      const urlparams = {
        scope: "openid conformance_testing",
        response_type: "code",
        redirect_uri: redirectUri,
        client_id: client.did,
        response_mode: "post",
        state: randomBytes(6).toString("hex"),
        authorization_details: JSON.stringify([
          {
            type: "openid_credential",
            credential_type: credentialType,
            format: "jwt_vc",
          },
        ]),
      };

      const urlParamsString = qs.stringify(urlparams);
      const response = await utils.httpCall.get(
        `${apiUrl}/issuer-mock/authorize?${urlParamsString}`,
        httpOpts
      );

      const urlResponse = (response.headers as { [x: string]: string })
        .location;

      const location = new URL(urlResponse).searchParams;

      if (location.get("error")) throw new Error(location.toString());

      return {
        code: location.get("code"),
        state: location.get("state"),
      };
    }
    case "issuerToken": {
      const code = readValue<string>(inputs[0]);
      const redirectUri =
        readValue<string>(inputs[1]) || "http://localhost:3000";
      Joi.assert(code, Joi.string());
      Joi.assert(redirectUri, Joi.string());

      const body = {
        code,
        grant_type: "authorization_code",
        redirect_uri: redirectUri,
      };

      const response = await utils.httpCall.post(
        `${apiUrl}/issuer-mock/token`,
        new URLSearchParams(body).toString(),
        httpOptsUrlencoded
      );
      return response.data;
    }
    case "issuerCredential": {
      const cNonce = readValue<string>(inputs[0]);
      const accessToken = readValue<string>(inputs[1]) || token;
      const alg = readValue<Alg>(inputs[2]) || "ES256K";
      const credentialType = readValue<string>(inputs[3]);
      const issuerUrl = readValue<string>(inputs[4]);

      Joi.assert(cNonce, Joi.string());

      if (!client.keys[alg])
        throw new Error(`There is no key defined for alg ${alg}`);
      const privateKey = await importJWK(client.keys[alg].privateKeyJwk, alg);
      const jwt = await new SignJWT({
        nonce: cNonce,
        aud: issuerUrl,
      })
        .setProtectedHeader({
          alg,
          typ: "JWT",
          kid: client.keys[alg].kid,
          ...(client.didVersion === 2 && {
            jwk: client.keys[alg].publicKeyJwk,
          }),
        })
        .setIssuedAt()
        .setIssuer(client.did)
        .sign(privateKey);

      const endpoint = "/issuer-mock/credential";
      const headers = {
        authorization: `Bearer ${accessToken}`,
      };
      const body = {
        type: credentialType,
        proof: {
          proof_type: "jwt",
          jwt,
        },
      };

      const response = await utils.httpCall.post(
        `${apiUrl}${endpoint}`,
        qs.stringify(body),
        {
          headers: { ...httpOpts.headers, ...headers },
        }
      );

      return response.data;
    }
    case "verifierAuthRequest": {
      const flowType = readValue<string>(inputs[0]) || "same-device";
      const redirect = readValue<string>(inputs[1]) || "false";

      const urlparams = { redirect, flow_type: flowType };

      let dataResponse: string;
      {
        const response = await utils.httpCall.get(
          `${apiUrl}/verifier-mock/authentication-requests?${qs.stringify(
            urlparams
          )}`,
          httpOpts
        );
        dataResponse = response.data as string;
      }
      const uriDecoded = qs.parse(dataResponse.replace("openid://?", "")) as {
        scope: string;
        response_type: string;
        client_id: string;
      };
      return uriDecoded;
    }
    case "verifierAuthResponse": {
      const jwtVp = readValue<string>(inputs[0]);
      const alg = readValue<Alg>(inputs[1]) || "ES256K";
      Joi.assert(jwtVp, Joi.string());

      if (!client.keys[alg])
        throw new Error(`There is no key defined for alg ${alg}`);
      const privateKey = await importJWK(client.keys[alg].privateKeyJwk, alg);
      const idToken = await new SignJWT({
        _vp_token: {
          presentation_submission: {
            id: randomUUID(),
            definition_id: "conformance_mock_vp_request",
            descriptor_map: [
              {
                id: "conformance_mock_vp",
                format: "jwt_vp",
                path: "$",
              },
            ],
          },
        },
      })
        .setProtectedHeader({
          alg,
          typ: "JWT",
          kid: client.keys[alg].kid,
          ...(client.didVersion === 2 && {
            jwk: client.keys[alg].publicKeyJwk,
          }),
        })
        .setIssuedAt()
        .setIssuer("https://self-issued.me/v2")
        .sign(privateKey);

      const body = {
        id_token: idToken,
        vp_token: jwtVp,
      };

      const response = await utils.httpCall.post(
        `${apiUrl}/verifier-mock/authentication-responses`,
        qs.stringify(body as Record<string, string>),
        httpOptsUrlencoded
      );
      return response.data;
    }
    case "issuer": {
      let response = await execCommand("conformance-old issuerInitiate", true);
      const { credential_type: credentialType, issuer: issuerUrl } =
        response as {
          credential_type: string;
          issuer: string;
        };

      response = await execCommand(
        `conformance-old issuerAuthorize http://localhost:3000 ${credentialType}`,
        true
      );
      const { code } = response as { code: string };
      response = await execCommand(`conformance-old issuerToken ${code}`, true);
      const { access_token: accessToken, c_nonce: cNonce } = response as {
        access_token: string;
        c_nonce: string;
      };
      response = await execCommand(
        `conformance-old issuerCredential ${cNonce} ${accessToken} ES256K ${credentialType} ${issuerUrl}`,
        true
      );
      return response;
    }
    case "verifier": {
      const { credential: jwtVc } = await execCommand<{ credential: string }>(
        `conformance-old issuer`,
        true
      );
      await execCommand(`conformance-old verifierAuthRequest`, true);
      const vcDecoded = await execCommand<{
        payload: { iss: string };
      }>(`compute decodeJWT ${jwtVc}`, true);
      const audience = vcDecoded.payload.iss;
      const jwtVp: string = await execCommand(
        `compute createPresentationJwt ${jwtVc} ES256K ${audience}`,
        true
      );
      const response = await execCommand(
        `conformance-old verifierAuthResponse ${jwtVp}`,
        true
      );
      return response;
    }
    default:
      utils.red(`Invalid method '${method}'`);
      break;
  }
  return 0;
}

async function smartContractApi(
  contract: string,
  method: string,
  ...inputs: (string | UnknownObject)[]
): Promise<unknown> {
  const apiUrl = (config.api[contract] as ConfigApi).url;
  if (method === "get") {
    const response = await utils.httpCall.get(
      `${apiUrl}${urlPath(inputs)}`,
      httpOpts
    );
    return response.data as unknown;
  }

  const url = `${apiUrl}/jsonrpc`;

  if (method === "sendSignedTransaction") {
    const unsignedTransaction = readValue<ethers.Transaction>(inputs[0]);
    const sgnTx = readValue<string>(inputs[1]);
    Joi.assert(unsignedTransaction, Joi.object());
    Joi.assert(sgnTx, Joi.string());
    const bodySend = jsonrpcBody(method, [
      paramSignedTransaction(unsignedTransaction, sgnTx),
    ]);
    const response = await utils.httpCall.post<JsonRpcResponse<string>>(
      url,
      bodySend,
      httpOpts
    );
    // use ledger proxy is besu provider is defined
    const context = {
      config,
      httpOpts,
      client,
      trustedApp,
      rtVars,
      transactionInfo,
      token,
      oauth2token,
    };
    const useProxy = !!config.besuProvider;
    transactionInfo.txId = response.data.result;
    transactionInfo.receipt = await waitToBeMined(
      response.data.result,
      useProxy,
      context
    );
    return transactionInfo.receipt;
  }

  if (!method.startsWith("build-")) {
    const inputsStr = inputs
      .map((input) =>
        typeof input === "string" ? input : JSON.stringify(input)
      )
      .join(" ");
    const uTx = await execCommand(
      `${contract} build-${method} ${inputsStr}`,
      true
    );
    const sgnTx = await execCommand<string>(
      `compute signTransaction ${JSON.stringify(uTx)}`,
      true
    );
    const receipt = await execCommand<string>(
      `${contract} sendSignedTransaction ${JSON.stringify(uTx)} ${sgnTx}`,
      true
    );
    await execCommand("view transactionInfo", true);
    return receipt;
  }

  let m = method.replace("build-", "");
  const build = await buildParam(
    contract,
    m,
    client,
    inputs.map((input) => readValue<string | UnknownObject>(input))
  );
  if (build.method) m = build.method.substring(0, build.method.indexOf("("));

  const param: {
    from: string;
    [x: string]: unknown;
  } = {
    from: client.ethWallet.address,
    ...build.param,
  };

  const body = jsonrpcBody(m, [param]);
  const response = await utils.httpCall.post<JsonRpcResponse>(
    url,
    body,
    httpOpts
  );

  utils.yellow(build.info.title);
  utils.yellow(build.info.data);

  transactionInfo = {
    contract,
    method: m,
    build,
  };
  return response.data.result;
}

function environment(env: SupportedEnvs) {
  if (env) {
    config = loadConfig(env);
    utils.yellow(`Environment ${env} loaded`);
  } else {
    utils.yellow(`Current environment: ${config.env}`);
  }
  const { domain, contractAddresses, api, env: envConfig } = config;
  utils.yellow({
    domain,
    contractAddresses,
    urls: Object.keys(api).map((name) => (api[name] as ConfigApi).url),
    env: envConfig,
  });
}

function setDomain(dom: string) {
  if (dom) {
    Object.keys(config.api).forEach((apiName) => {
      (config.api[apiName] as ConfigApi).url = (
        config.api[apiName] as ConfigApi
      ).url.replace(config.domain, dom);
    });
    config.domain = dom;
  }
  utils.yellow(`Current domain: ${config.domain}`);
}

function wctOld(method: string, inputs: (string | UnknownObject)[]): unknown {
  switch (method) {
    case "loadReport": {
      const filename = readValue<string>(inputs[0]);
      Joi.assert(filename, Joi.string());
      const data = fs.readFileSync(filename, "utf8");
      const book = JSON.parse(data) as unknown;
      utils.yellow(`Report loaded: ${filename}`);
      return book;
    }
    case "check": {
      const logs = readValue<ConformanceLog[]>(inputs[0]);
      if (!logs || logs.length === 0) throw new Error("No logs found");
      const iniTime = new Date(logs[0].created).toISOString();
      const endTime = new Date(logs[logs.length - 1].created).toISOString();
      const conformanceId = logs[0].data.request.headers.conformance;

      console.log(
        [
          "",
          chalk.yellow("----------------------------------------------------"),
          chalk.yellow("Wallet Conformance Testing Report"),
          chalk.yellow("----------------------------------------------------"),
          "",
          `conformance id: ${chalk.magenta(conformanceId)}`,
          "",
          "timestamp:",
          `  from: ${chalk.magenta(iniTime)}`,
          `  to:   ${chalk.magenta(endTime)}`,
          "",
        ].join("\n")
      );

      const missingUrls = [
        "/conformance/v2/issuer-mock/initiate",
        "/conformance/v2/issuer-mock/authorize",
        "/conformance/v2/issuer-mock/token",
        "/conformance/v2/issuer-mock/credential",
        "/conformance/v2/verifier-mock/authentication-requests",
        "/conformance/v2/verifier-mock/authentication-responses",
      ];

      let numberErrors = 0;
      logs.forEach((log) => {
        const testOk = log.data.response.statusCode < 400;
        const url = log.data.request.url.split("?")[0];
        const result = testOk ? chalk.green("OK") : chalk.red("FAIL");
        console.log(url + ".".repeat(70 - url.length) + result);
        if (!testOk) numberErrors += 1;
        const id = missingUrls.findIndex((u) => u === url);
        if (id >= 0) missingUrls.splice(id, 1);
      });
      missingUrls.forEach((url) => {
        console.log(url + ".".repeat(70 - url.length) + chalk.red("NO LOGS"));
      });
      numberErrors += missingUrls.length;
      console.log("");
      const numberSuccess = logs.length + missingUrls.length - numberErrors;
      if (numberSuccess)
        console.log(
          chalk.green.bold(numberSuccess) + chalk.green(" test passed")
        );
      if (numberErrors)
        console.log(chalk.red.bold(numberErrors) + chalk.red(" test failed"));
      return 0;
    }
    default:
      utils.red(`Invalid method '${method}'`);
      break;
  }
  return 0;
}

function fileSystem(
  method: string,
  ...params: (string | UnknownObject)[]
): unknown {
  switch (method) {
    case "readBinaryFile": {
      const [filename] = params as string[];
      Joi.assert(filename, Joi.string());
      return fs.readFileSync(filename);
    }
    case "writeBinaryFile": {
      const filename = readValue<string>(params[0]);
      const data = readValue<Uint8Array>(params[1]);
      Joi.assert(filename, Joi.string());
      fs.writeFileSync(filename, data);
      return 0;
    }
    default:
      utils.red(`Invalid method '${method}'`);
      return 0;
  }
}

async function run(filename: string, inputs: unknown[] = []): Promise<unknown> {
  const lines = fs.readFileSync(`scripts/${filename}`, "utf8").split(/\r?\n/);
  let response: unknown;
  for (let i = 0; i < lines.length; i += 1) {
    let line = lines[i].trim();
    inputs.forEach((input, j) => {
      const param = typeof input === "string" ? input : JSON.stringify(input);
      line = line.replace(new RegExp(`\\$${j + 1}`, "g"), param);
    });
    try {
      if (line.length > 0 && !line.startsWith("#")) {
        response = await execCommand(line, true);
      }
    } catch (error) {
      utils.red((error as Error).stack);
      throw new Error(`Error in line ${i + 1}: ${(error as Error).message}`);
    }
  }
  return response;
}

export async function execCommand<T = unknown>(
  command: string,
  printCommand = false
): Promise<T> {
  if (printCommand) console.log(`==> ${command}`);
  const parts = parseLine(command);
  let varName = "";
  if (parts.length === 0) return 0 as unknown as T;
  if (typeof parts[0] === "string" && parts[0].includes(":")) {
    varName = parts[0].replace(":", "");
    parts.shift();
  }
  const [part0, part1] = parts;
  const parts2 = parts.slice(2);

  const method = part0 as string;
  const word1 = part1 as string;

  Joi.assert(method, Joi.string());

  // APIs linked to smart contracts
  if (
    [
      "timestamp",
      "timestamp-new",
      "did",
      "did-old",
      "did-new",
      "tar",
      "tar-new",
      "tir",
      "tir-old",
      "tir-new",
      "tsr",
      "tsr-new",
      "tpr",
      "tpr-new",
    ].includes(method)
  ) {
    Joi.assert(word1, Joi.string());
    const response = await smartContractApi(method, word1, ...parts2);
    if (varName) await setVar(varName, response);
    return response as T;
  }

  const schemaStrings = Joi.array().items(Joi.string());

  const context = {
    config,
    httpOpts,
    client,
    trustedApp,
    rtVars,
    transactionInfo,
    token,
    oauth2token,
  };

  // Other APIs and configurations
  switch (method) {
    case "fs": {
      Joi.assert(word1, Joi.string());
      const response = fileSystem(word1, ...parts2);
      console.log(response);
      if (varName) await setVar(varName, response);
      return response as T;
    }
    case "set": {
      Joi.assert(word1, Joi.string());
      const inputs = parts2.map((p) => readValue<unknown>(p));
      let value = inputs[0];
      if (inputs.length > 1) {
        Joi.assert(inputs, schemaStrings);
        value = inputs.join("");
      }
      await setVar(word1, value);
      return value as T;
    }
    case "view": {
      Joi.assert(word1, Joi.string());
      return view([readValue(word1)], context) as T;
    }
    case "using": {
      Joi.assert(word1, Joi.string());
      const user = await using(word1, ...parts2);
      return user as T;
    }
    case "env": {
      Joi.assert(word1, Joi.string().optional());
      const input = readValue<SupportedEnvs>(word1);
      environment(input);
      return 0 as unknown as T;
    }
    case "domain": {
      Joi.assert(word1, Joi.string());
      setDomain(word1);
      return 0 as unknown as T;
    }
    case "authorisation": {
      Joi.assert(word1, Joi.string());
      Joi.assert(parts2, schemaStrings);
      const inputs = parts2.map((p) => readValue<string>(p));
      const response = await authorisationV3(word1, inputs, context);
      if (varName) await setVar(varName, response);
      return response as T;
    }
    case "authorisation-new": {
      Joi.assert(word1, Joi.string());
      Joi.assert(parts2, schemaStrings);
      const inputs = parts2.map((p) => readValue<string>(p));
      const response = await authorisationV4(word1, inputs, context);
      if (varName) await setVar(varName, response);
      return response as T;
    }
    case "authorisation-old": {
      Joi.assert(word1, Joi.string());
      Joi.assert(parts2, schemaStrings);
      const response = await authorisationV2(word1, parts2 as string[]);
      if (varName) await setVar(varName, response);
      return response as T;
    }
    case "notifications": {
      Joi.assert(word1, Joi.string());
      const response = await notifications(word1, ...parts2);
      if (varName) await setVar(varName, response);
      return response as T;
    }
    case "datahub": {
      Joi.assert(word1, Joi.string());
      const response = await proxydatahub(word1, parts2);
      if (varName) await setVar(varName, response);
      return response as T;
    }
    case "storage": {
      Joi.assert(word1, Joi.string());
      const response = await storage(word1, parts2);
      if (varName) await setVar(varName, response);
      return response as T;
    }
    case "cassandra": {
      Joi.assert(word1, Joi.string());
      const response = await cassandra(word1, parts2);
      if (varName) await setVar(varName, response);
      return response as unknown as T;
    }
    case "proxyledger": {
      Joi.assert(word1, Joi.string());
      const inputs = parts2.map((p) => readValue<string | UnknownObject>(p));
      const response = await ledgerV4(word1, inputs, true, context);
      if (varName) await setVar(varName, response);
      return response as T;
    }
    case "ledger": {
      Joi.assert(word1, Joi.string());
      const inputs = parts2.map((p) => readValue<string | UnknownObject>(p));
      const response = await ledgerV3(word1, inputs, false, context);
      if (varName) await setVar(varName, response);
      return response as T;
    }
    case "ledger-new": {
      Joi.assert(word1, Joi.string());
      const inputs = parts2.map((p) => readValue<string | UnknownObject>(p));
      const response = await ledgerV4(word1, inputs, false, context);
      if (varName) await setVar(varName, response);
      return response as T;
    }
    case "onboarding": {
      Joi.assert(word1, Joi.string());
      Joi.assert(parts2, schemaStrings);
      const response = await onboarding(word1, ...(parts2 as string[]));
      if (varName) await setVar(varName, response);
      return response as T;
    }
    case "conformance": {
      Joi.assert(word1, Joi.string());
      const inputs = parts2.map((p) => readValue<string | UnknownObject>(p));
      const response = await conformanceV3(word1, inputs, context);
      if (varName) await setVar(varName, response);
      return response as T;
    }
    case "conformance-new": {
      Joi.assert(word1, Joi.string());
      const inputs = parts2.map((p) => readValue<string | UnknownObject>(p));
      const response = await conformanceV4(word1, inputs, context);
      if (varName) await setVar(varName, response);
      return response as T;
    }
    case "conformance-old": {
      Joi.assert(word1, Joi.string());
      const response = await conformanceOld(word1, parts2);
      if (varName) await setVar(varName, response);
      return response as T;
    }
    case "compute": {
      Joi.assert(word1, Joi.string());
      const inputs = parts2.map((p) => readValue<UnknownObject | string>(p));
      const response = await compute(word1, inputs, context);
      if (varName) await setVar(varName, response);
      return response as T;
    }
    case "load": {
      const filename = readValue<string>(word1);
      const data = fs.readFileSync(filename, "utf8");
      const response = JSON.parse(data) as unknown;
      if (varName) await setVar(varName, response);
      return response as T;
    }
    case "wct-old": {
      Joi.assert(word1, Joi.string());
      const response = wctOld(word1, parts2);
      if (varName) await setVar(varName, response, false);
      return response as T;
    }
    case "run": {
      Joi.assert(word1, Joi.string());
      const inputs = parts2.map((p) => readValue<string>(p));
      const response = await run(word1, inputs);
      if (varName) await setVar(varName, response);
      return response as T;
    }
    case "exit": {
      process.exit(0);
      return 0 as unknown as T;
    }
    default:
      utils.red(`Invalid method '${method}'`);
      return 0 as unknown as T;
  }
}

export async function main(): Promise<void> {
  const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout,
  });

  // eslint-disable-next-line no-constant-condition
  while (true) {
    const command: string = await new Promise((resolve) => {
      rl.question("==> ", (input) => {
        resolve(input);
      });
    });
    try {
      await execCommand(command);
    } catch (error) {
      utils.red((error as Error).stack);
    }
  }
}
