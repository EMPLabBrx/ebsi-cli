import crypto from "node:crypto";
import Joi from "joi";
import { EbsiWallet } from "@cef-ebsi/wallet-lib";
import {
  BuildParamResponse,
  UnknownObject,
} from "../interfaces/shared/index.js";
import { Client } from "../utils/Client.js";

export function buildParamTar(
  method: string,
  client: Client,
  inputs: (string | UnknownObject)[]
): BuildParamResponse {
  switch (method) {
    case "setRegistryAddresses": {
      return {
        info: { title: "initialization", data: method },
        param: {},
      };
    }
    case "insertPolicy": {
      const [inputPolicyId, inputPolicy] = inputs as [string, UnknownObject];
      Joi.assert(inputPolicyId, Joi.string().optional());
      Joi.assert(inputPolicy, Joi.object().optional());
      const policyId =
        inputPolicyId || `policy-${crypto.randomBytes(5).toString("hex")}`;
      const policy =
        typeof inputPolicy === "object"
          ? inputPolicy
          : { policy: crypto.randomBytes(12).toString("hex") };
      const buffer = Buffer.from(JSON.stringify(policy));

      return {
        info: { title: `Insert policy ${policyId}`, data: policy },
        param: {
          policyId,
          policyData: `0x${buffer.toString("hex")}`,
        },
      };
    }
    case "updatePolicy": {
      const [policyId, inputPolicy] = inputs as [string, UnknownObject];
      Joi.assert(policyId, Joi.string());
      Joi.assert(inputPolicy, Joi.object().optional());
      const policy =
        typeof inputPolicy === "object"
          ? inputPolicy
          : { policy: crypto.randomBytes(12).toString("hex") };
      const buffer = Buffer.from(JSON.stringify(policy));

      return {
        info: { title: `Update policy ${policyId}`, data: policy },
        param: {
          policyId,
          policyData: `0x${buffer.toString("hex")}`,
        },
      };
    }
    case "insertAuthorization": {
      const [
        name,
        authorizedAppName,
        inputIss,
        inputStatus,
        inputPermissions,
        inputNotBefore,
        inputNotAfter,
      ] = inputs as [
        string,
        string,
        UnknownObject,
        UnknownObject,
        UnknownObject,
        UnknownObject,
        UnknownObject
      ];
      Joi.assert(name, Joi.string());
      Joi.assert(authorizedAppName, Joi.string());
      Joi.assert(inputIss, Joi.string().optional());
      Joi.assert(inputStatus, Joi.string().optional());
      Joi.assert(inputPermissions, Joi.string().optional());
      Joi.assert(inputNotBefore, Joi.string().optional());
      Joi.assert(inputNotAfter, Joi.string().optional());

      const now = Math.round(Date.now() / 1000);
      const iss = inputIss || client.did;
      const status = Number(inputStatus) || 1;
      const permissions = Number(inputPermissions) || 15;
      const notBefore = Number(inputNotBefore) || now;
      const notAfter = Number(inputNotAfter) || 0;
      return {
        info: {
          title: "Authorisation",
          data: `${authorizedAppName} to access ${name}`,
        },
        param: {
          name,
          authorizedAppName,
          iss,
          status,
          permissions,
          notBefore,
          notAfter,
        },
      };
    }
    case "updateAuthorization": {
      const [authorizationId, inputStatus, inputPermissions, inputNotAfter] =
        inputs as string[];
      Joi.assert(authorizationId, Joi.string());
      Joi.assert(inputStatus, Joi.string().optional());
      Joi.assert(inputPermissions, Joi.string().optional());
      Joi.assert(inputNotAfter, Joi.string().optional());

      const status = Number(inputStatus) || 1;
      const permissions = Number(inputPermissions) || 15;
      const notAfter = Number(inputNotAfter) || 0;

      return {
        info: {
          title: `Authorisation ${authorizationId}`,
          data: `status ${status}, permissions ${permissions}`,
        },
        param: {
          authorizationId,
          status,
          permissions,
          notAfter,
        },
      };
    }
    case "insertApp": {
      const [name, inputAppAdministrator] = inputs as string[];
      const appAdministrator = inputAppAdministrator || client.did;
      Joi.assert(name, Joi.string());
      Joi.assert(appAdministrator, Joi.string());

      return {
        info: {
          title: "Insert App",
          data: name,
        },
        param: {
          name,
          domain: 1,
          appAdministrator,
        },
      };
    }
    case "updateApp": {
      const [applicationId, inputDomain] = inputs as string[];
      Joi.assert(applicationId, Joi.string());
      Joi.assert(inputDomain, Joi.string().optional());
      const domain = Number(inputDomain) || 1;
      return {
        info: {
          title: `App ${applicationId}`,
          data: `domain ${domain}`,
        },
        param: {
          applicationId,
          domain,
        },
      };
    }
    case "insertAppInfo": {
      const [applicationId, info] = inputs as [string, UnknownObject];
      Joi.assert(applicationId, Joi.string());
      Joi.assert(info, Joi.object());
      const infoBytes = `0x${Buffer.from(JSON.stringify(info)).toString(
        "hex"
      )}`;
      return {
        info: {
          title: `App info`,
          data: info,
        },
        param: {
          applicationId,
          info: infoBytes,
        },
      };
    }
    case "insertAppPublicKey": {
      const [applicationId, key, inputStatus, inputNotBefore, inputNotAfter] =
        inputs as string[];
      Joi.assert(applicationId, Joi.string());
      Joi.assert(key, Joi.string());
      Joi.assert(inputStatus, Joi.string().optional());
      Joi.assert(inputNotBefore, Joi.string().optional());
      Joi.assert(inputNotAfter, Joi.string().optional());
      const now = Math.round(Date.now() / 1000);
      let publicKeyPem: string;
      if (key.length <= 66) {
        // using private key
        publicKeyPem = new EbsiWallet(key).getPublicKey({
          format: "pem",
        });
      } else {
        // using public key
        publicKeyPem = Buffer.from(key, "base64").toString("utf8");
      }

      const publicKey = `0x${Buffer.from(publicKeyPem, "utf8").toString(
        "hex"
      )}`;

      const status = Number(inputStatus) || 1;
      const notBefore = Number(inputNotBefore) || now;
      const notAfter = Number(inputNotAfter) || 0;
      return {
        info: {
          title: "Insert App Public Key",
          data: publicKeyPem,
        },
        param: {
          applicationId,
          publicKey,
          status,
          notBefore,
          notAfter,
        },
      };
    }
    case "updateAppPublicKey": {
      const [publicKeyId, inputStatus, inputNotAfter] = inputs as string[];
      Joi.assert(publicKeyId, Joi.string());
      Joi.assert(inputStatus, Joi.string().optional());
      Joi.assert(inputNotAfter, Joi.string().optional());
      const status = Number(inputStatus) || 1;
      const notAfter = Number(inputNotAfter) || 0;
      return {
        info: {
          title: "Update App Public Key",
          data: `status ${status}`,
        },
        param: {
          publicKeyId,
          status,
          notAfter,
        },
      };
    }
    case "insertAppAdministrator":
    case "deleteAppAdministrator": {
      const [applicationId, administratorId] = inputs as string[];
      Joi.assert(applicationId, Joi.string());
      Joi.assert(administratorId, Joi.string());
      return {
        info: {
          title: "Insert App Administrator",
          data: { applicationId, administratorId },
        },
        param: { applicationId, administratorId },
      };
    }
    case "insertRevocation": {
      const [applicationId, revokedBy, inputNotBefore] = inputs as string[];
      Joi.assert(applicationId, Joi.string());
      Joi.assert(revokedBy, Joi.string());
      Joi.assert(inputNotBefore, Joi.string().optional());

      const now = Math.round(Date.now() / 1000);
      const notBefore = Number(inputNotBefore) || now;
      return {
        info: {
          title: "Insert Revocation",
          data: `Revoked by ${revokedBy}`,
        },
        param: {
          applicationId,
          revokedBy,
          notBefore,
        },
      };
    }
    default:
      throw new Error(`Invalid method '${method}'`);
  }
}

export default buildParamTar;
