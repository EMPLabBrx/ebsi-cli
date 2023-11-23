import Joi from "joi";
import { ethers } from "ethers";
import { EbsiWallet } from "@cef-ebsi/wallet-lib";
import {
  BuildParamResponse,
  UnknownObject,
} from "../interfaces/shared/index.js";
import { Client } from "../utils/Client.js";

export function buildParamTarV3(
  method: string,
  client: Client,
  inputs: (string | UnknownObject)[]
): BuildParamResponse {
  switch (method) {
    case "insertAuthorization": {
      const [name, authorizedAppName, inputIss, inputStatus] = inputs as [
        string,
        string,
        UnknownObject,
        UnknownObject
      ];
      Joi.assert(name, Joi.string());
      Joi.assert(authorizedAppName, Joi.string());
      Joi.assert(inputIss, Joi.string().optional());
      Joi.assert(inputStatus, Joi.string().optional());

      const iss = inputIss || client.did;
      const status = Number(inputStatus) || 1;
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
        },
      };
    }
    case "updateAuthorization": {
      const [authorizationId, inputStatus] = inputs as string[];
      Joi.assert(authorizationId, Joi.string());
      Joi.assert(inputStatus, Joi.string().optional());

      const status = Number(inputStatus) || 1;

      return {
        info: {
          title: `Authorisation ${authorizationId}`,
          data: `status ${status}`,
        },
        param: {
          authorizationId,
          status,
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
      const [applicationIdOrName, key, inputStatus] = inputs as string[];
      let applicationId = "";
      if (applicationIdOrName.startsWith("0x")) {
        applicationId = applicationIdOrName;
      } else {
        applicationId = ethers.utils.sha256(Buffer.from(applicationIdOrName));
      }
      Joi.assert(applicationId, Joi.string());
      Joi.assert(key, Joi.string());
      Joi.assert(inputStatus, Joi.string().optional());
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
      return {
        info: {
          title: "Insert App Public Key",
          data: publicKeyPem,
        },
        param: {
          applicationId,
          publicKey,
          status,
        },
      };
    }
    case "updateAppPublicKey": {
      const [publicKeyId, inputStatus] = inputs as string[];
      Joi.assert(publicKeyId, Joi.string());
      Joi.assert(inputStatus, Joi.string().optional());
      const status = Number(inputStatus) || 1;
      return {
        info: {
          title: "Update App Public Key",
          data: `status ${status}`,
        },
        param: {
          publicKeyId,
          status,
        },
      };
    }
    case "insertAppAdministrator": {
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
    case "deleteAppAdministrator": {
      const [applicationId, administratorId] = inputs as string[];
      Joi.assert(applicationId, Joi.string());
      Joi.assert(administratorId, Joi.string());
      return {
        info: {
          title: "Delete App Administrator",
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

export default buildParamTarV3;
