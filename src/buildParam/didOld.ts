import { ethers } from "ethers";
import crypto from "node:crypto";
import Joi from "joi";
import {
  BuildParamResponse,
  UnknownObject,
} from "../interfaces/shared/index.js";
import { Client } from "../utils/Client.js";

const { sha256 } = ethers.utils;

function createMetadata(): UnknownObject {
  return {
    meta: crypto.randomBytes(32).toString("hex"),
  };
}

function createTimestamp(): UnknownObject {
  return {
    data: crypto.randomBytes(32).toString("hex"),
  };
}

function computeIdentifier(did: string): string {
  return `0x${Buffer.from(did).toString("hex")}`;
}

export function randomOid(): string {
  return `1.3.6.1.4.1.${Math.ceil(Math.random() * 2020)}.${Math.ceil(
    Math.random() * 10
  )}.${Math.ceil(Math.random() * 250)}.${Math.ceil(
    Math.random() * 3
  )}.${Math.ceil(Math.random() * 3)}.${Math.ceil(
    Math.random() * 3
  )}.${Math.ceil(Math.random() * 100)}`;
}

export function buildParamDidOld(
  method: string,
  client: Client,
  inputs: (string | UnknownObject)[]
): BuildParamResponse {
  switch (method) {
    case "setTrustedPoliciesRegistryAddress": {
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
    case "insertHashAlgorithm": {
      const [
        inputOutputLength,
        inputIanaName,
        inputOid,
        inputStatus,
        inputMultihash,
      ] = inputs as string[];
      Joi.assert(inputOutputLength, Joi.string().optional());
      Joi.assert(inputIanaName, Joi.string().optional());
      Joi.assert(inputOid, Joi.string().optional());
      Joi.assert(inputStatus, Joi.string().optional());
      Joi.assert(inputMultihash, Joi.string().optional());
      const outputLength = Number(inputOutputLength) || 1;
      const ianaName = inputIanaName || "undefined";
      const oid = inputOid || "undefined";
      const status = Number(inputStatus) || 1;
      const multihash = inputMultihash || ianaName;
      return {
        info: {
          title: "Hash Algorithm",
          data: ianaName,
        },
        param: {
          outputLength,
          ianaName,
          oid,
          status,
          multihash,
        },
      };
    }
    case "updateHashAlgorithm": {
      const [
        inputHashAlgorithmId,
        inputOutputLength,
        inputIanaName,
        inputOid,
        inputStatus,
        inputMultihash,
      ] = inputs as string[];
      Joi.assert(inputHashAlgorithmId, Joi.string());
      Joi.assert(inputOutputLength, Joi.string().optional());
      Joi.assert(inputIanaName, Joi.string().optional());
      Joi.assert(inputOid, Joi.string().optional());
      Joi.assert(inputStatus, Joi.string().optional());
      Joi.assert(inputMultihash, Joi.string().optional());
      const hashAlgorithmId = Number(inputHashAlgorithmId);
      const outputLength = Number(inputOutputLength) || 1;
      const ianaName = inputIanaName || "undefined";
      const oid = inputOid || "undefined";
      const status = Number(inputStatus) || 1;
      const multihash = inputMultihash || ianaName;

      return {
        info: {
          title: "Hash Algorithm",
          data: ianaName,
        },
        param: {
          hashAlgorithmId,
          outputLength,
          ianaName,
          oid,
          status,
          multihash,
        },
      };
    }
    case "insertDidDocument":
    case "updateDidDocument": {
      const [inputControllerDid, inputDocument, inputMetadata, inputTimestamp] =
        inputs as [string, UnknownObject, UnknownObject, UnknownObject];
      Joi.assert(inputControllerDid, Joi.string().optional());
      Joi.assert(inputDocument, Joi.object().optional());
      Joi.assert(inputMetadata, Joi.object().optional());
      Joi.assert(inputTimestamp, Joi.object().optional());
      const controllerDid = inputControllerDid || client.did;
      const document =
        typeof inputDocument === "object"
          ? inputDocument
          : client.generateDidDocument();
      const metadata =
        typeof inputMetadata === "object" ? inputMetadata : createMetadata();
      const timestamp =
        typeof inputTimestamp === "object" ? inputTimestamp : createTimestamp();

      const bufferDocument = Buffer.from(JSON.stringify(document));
      const bufferTimestamp = Buffer.from(JSON.stringify(timestamp));
      const bufferMetadata = Buffer.from(JSON.stringify(metadata));
      const documentHash = sha256(bufferDocument);

      return {
        info: {
          title: "Did document",
          data: document,
        },
        param: {
          identifier: computeIdentifier(controllerDid),
          hashAlgorithmId: 1, // sha256
          hashValue: documentHash,
          didVersionInfo: `0x${bufferDocument.toString("hex")}`,
          timestampData: `0x${bufferTimestamp.toString("hex")}`,
          didVersionMetadata: `0x${bufferMetadata.toString("hex")}`,
        },
      };
    }
    case "insertDidController":
    case "updateDidController": {
      const [did, newControllerId, inputNotBefore, inputNotAfter] =
        inputs as string[];
      Joi.assert(did, Joi.string());
      Joi.assert(newControllerId, Joi.string());
      Joi.assert(inputNotBefore, Joi.string().optional());
      Joi.assert(inputNotAfter, Joi.string().optional());
      const now = Math.round(Date.now() / 1000);
      const notBefore = Number(inputNotBefore) || now;
      const notAfter = Number(inputNotAfter) || 0;
      return {
        info: {
          title: "Did controller",
          data: newControllerId,
        },
        param: {
          identifier: computeIdentifier(did),
          newControllerId,
          notBefore,
          notAfter,
        },
      };
    }
    case "revokeDidController": {
      const [did, oldControllerId] = inputs as string[];
      Joi.assert(did, Joi.string());
      Joi.assert(oldControllerId, Joi.string());
      return {
        info: {
          title: "Did controller",
          data: oldControllerId,
        },
        param: {
          identifier: computeIdentifier(did),
          oldControllerId,
        },
      };
    }
    case "appendDidDocumentVersionHash": {
      const [inputControllerDid, inputDocument, inputTimestamp] = inputs as [
        string,
        UnknownObject,
        UnknownObject
      ];
      Joi.assert(inputControllerDid, Joi.string().optional());
      Joi.assert(inputDocument, Joi.object().optional());
      Joi.assert(inputTimestamp, Joi.object().optional());
      const controllerDid = inputControllerDid || client.did;
      const document =
        typeof inputDocument === "object"
          ? inputDocument
          : client.generateDidDocument();
      const timestamp =
        typeof inputTimestamp === "object" ? inputTimestamp : createTimestamp();

      const bufferDocument = Buffer.from(JSON.stringify(document));
      const bufferTimestamp = Buffer.from(JSON.stringify(timestamp));
      const documentHash = sha256(bufferDocument);

      return {
        info: {
          title: "Did document version hash",
          data: {
            document,
            timestamp,
          },
        },
        param: {
          identifier: computeIdentifier(controllerDid),
          hashAlgorithmId: 1, // sha256
          hashValue: documentHash,
          timestampData: `0x${bufferTimestamp.toString("hex")}`,
          didVersionInfo: `0x${bufferDocument.toString("hex")}`,
        },
      };
    }
    case "detachDidDocumentVersionHash": {
      const [inputControllerDid, inputDocument] = inputs as [
        string,
        UnknownObject
      ];
      Joi.assert(inputControllerDid, Joi.string().optional());
      Joi.assert(inputDocument, Joi.object().optional());
      const controllerDid = inputControllerDid || client.did;
      const document =
        typeof inputDocument === "object"
          ? inputDocument
          : client.generateDidDocument();

      const bufferDocument = Buffer.from(JSON.stringify(document));
      const documentHash = sha256(bufferDocument);

      return {
        info: {
          title: "Detach did document version hash",
          data: {
            document,
          },
        },
        param: {
          identifier: computeIdentifier(controllerDid),
          hashAlgorithmId: 1, // sha256
          hashValue: documentHash,
          didVersionInfo: `0x${bufferDocument.toString("hex")}`,
        },
      };
    }
    case "appendDidDocumentVersionMetadata":
    case "detachDidDocumentVersionMetadata": {
      const [inputControllerDid, inputDocument, inputMetadata] = inputs as [
        string,
        UnknownObject,
        UnknownObject
      ];
      Joi.assert(inputControllerDid, Joi.string().optional());
      Joi.assert(inputDocument, Joi.object().optional());
      Joi.assert(inputMetadata, Joi.object().optional());
      const controllerDid = inputControllerDid || client.did;
      const document =
        typeof inputDocument === "object"
          ? inputDocument
          : client.generateDidDocument();
      const metadata =
        typeof inputMetadata === "object" ? inputMetadata : createMetadata();

      const bufferDocument = Buffer.from(JSON.stringify(document));
      const bufferMetadata = Buffer.from(JSON.stringify(metadata));

      return {
        info: {
          title: "Append did document version metadata",
          data: {
            document,
            metadata,
          },
        },
        param: {
          identifier: computeIdentifier(controllerDid),
          didVersionInfo: `0x${bufferDocument.toString("hex")}`,
          didVersionMetadata: `0x${bufferMetadata.toString("hex")}`,
        },
      };
    }
    default:
      throw new Error(`Invalid method '${method}'`);
  }
}

export default buildParamDidOld;
