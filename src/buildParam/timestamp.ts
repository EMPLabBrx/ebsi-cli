import crypto from "node:crypto";
import { ethers } from "ethers";
import Multihash from "multihashes";
import Joi from "joi";
import { multibaseEncode, fromHexString } from "../utils/index.js";
import {
  BuildParamResponse,
  UnknownObject,
} from "../interfaces/shared/index.js";
import { Client } from "../utils/Client.js";

const { sha256 } = ethers.utils;

export function buildParamTimestamp(
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
    case "timestampRecordHashes": {
      const [inputData, inputInfo] = inputs as UnknownObject[];
      Joi.assert(inputData, Joi.object().optional());
      Joi.assert(inputInfo, Joi.object().optional());
      const data =
        typeof inputData === "object"
          ? inputData
          : { test: crypto.randomBytes(12).toString("hex") };
      const buffer = Buffer.from(JSON.stringify(data));
      const info =
        typeof inputInfo === "object"
          ? inputInfo
          : {
              info: crypto.randomBytes(12).toString("hex"),
            };
      const timestamp = {
        hash: {
          id: 1,
          value: sha256(buffer),
        },
        data: `0x${buffer.toString("hex")}`,
      };

      return {
        info: {
          title: "Timestamp record hashes. Record Id:",
          data: { hashValue: timestamp.hash.value },
        },
        param: {
          hashAlgorithmIds: [timestamp.hash.id],
          hashValues: [timestamp.hash.value],
          timestampData: [timestamp.data],
          versionInfo: `0x${Buffer.from(JSON.stringify(info)).toString("hex")}`,
        },
      };
    }
    case "timestampVersionHashes": {
      const [versionHash, inputData, inputInfo] = inputs as [
        string,
        UnknownObject,
        UnknownObject
      ];
      Joi.assert(versionHash, Joi.string());
      Joi.assert(inputData, Joi.object().optional());
      Joi.assert(inputInfo, Joi.object().optional());
      const data =
        typeof inputData === "object"
          ? inputData
          : { test: crypto.randomBytes(12).toString("hex") };
      const buffer = Buffer.from(JSON.stringify(data));
      const info =
        typeof inputInfo === "object"
          ? inputInfo
          : {
              info: crypto.randomBytes(12).toString("hex"),
            };
      const timestamp = {
        hash: {
          id: 1,
          value: sha256(buffer),
        },
        data: `0x${buffer.toString("hex")}`,
      };

      return {
        info: {
          title: "Timestamp record version hashes",
          data: { data, info },
        },
        param: {
          versionHash,
          hashAlgorithmIds: [timestamp.hash.id],
          hashValues: [timestamp.hash.value],
          timestampData: [timestamp.data],
          versionInfo: `0x${Buffer.from(JSON.stringify(info)).toString("hex")}`,
        },
      };
    }
    case "timestampRecordVersionHashes": {
      const [recordId, inputData, inputInfo] = inputs as [
        string,
        UnknownObject,
        UnknownObject
      ];
      Joi.assert(recordId, Joi.string());
      Joi.assert(inputData, Joi.object().optional());
      Joi.assert(inputInfo, Joi.object().optional());
      const data =
        typeof inputData === "object"
          ? inputData
          : { test: crypto.randomBytes(12).toString("hex") };
      const buffer = Buffer.from(JSON.stringify(data));
      const info =
        typeof inputInfo === "object"
          ? inputInfo
          : {
              info: crypto.randomBytes(12).toString("hex"),
            };
      const timestamp = {
        hash: {
          id: 1,
          value: sha256(buffer),
        },
        data: `0x${buffer.toString("hex")}`,
      };

      return {
        info: {
          title: "Timestamp record version hashes",
          data: { data, info },
        },
        param: {
          recordId,
          hashAlgorithmIds: [timestamp.hash.id],
          hashValues: [timestamp.hash.value],
          timestampData: [timestamp.data],
          versionInfo: `0x${Buffer.from(JSON.stringify(info)).toString("hex")}`,
        },
      };
    }
    case "insertRecordOwner": {
      const [recordId, ownerId, inputNotBefore, inputNotAfter] =
        inputs as string[];
      Joi.assert(recordId, Joi.string());
      Joi.assert(ownerId, Joi.string());
      Joi.assert(inputNotBefore, Joi.string().optional());
      Joi.assert(inputNotAfter, Joi.string().optional());
      const now = Math.round(Date.now() / 1000);
      const notBefore = inputNotBefore || now;
      const notAfter = inputNotAfter || 0;

      return {
        info: {
          title: "Insert Record Owner",
          data: ownerId,
        },
        param: {
          recordId,
          ownerId,
          notBefore,
          notAfter,
        },
      };
    }
    case "revokeRecordOwner": {
      const [recordId, ownerId] = inputs as string[];
      Joi.assert(recordId, Joi.string());
      Joi.assert(ownerId, Joi.string());

      return {
        info: {
          title: "Revoke Record Owner",
          data: ownerId,
        },
        param: {
          recordId,
          ownerId,
        },
      };
    }
    case "insertRecordVersionInfo": {
      const [recordId, inputVersionId, inputInfo] = inputs as [
        string,
        string,
        UnknownObject
      ];
      Joi.assert(recordId, Joi.string());
      Joi.assert(inputVersionId, Joi.string());
      Joi.assert(inputInfo, Joi.object().optional());
      const versionId = Number(inputVersionId);
      const info =
        typeof inputInfo === "object"
          ? inputInfo
          : {
              info: crypto.randomBytes(12).toString("hex"),
            };

      return {
        info: {
          title: "Insert Record Version Info",
          data: { recordId, versionId, info },
        },
        param: {
          recordId,
          versionId,
          versionInfo: `0x${Buffer.from(JSON.stringify(info)).toString("hex")}`,
        },
      };
    }
    case "detachRecordVersionHash": {
      const [recordId, inputVersionId, hashValue] = inputs as string[];
      Joi.assert(recordId, Joi.string());
      Joi.assert(inputVersionId, Joi.string());
      Joi.assert(hashValue, Joi.string());
      const versionId = Number(inputVersionId);

      return {
        info: {
          title: "Detach Record Version Hash",
          data: { recordId, versionId, hashValue },
        },
        param: {
          recordId,
          versionId,
          hashValue,
        },
      };
    }
    case "appendRecordVersionHashes": {
      const [recordId, inputVersionId, inputData, inputInfo] =
        inputs as string[];
      Joi.assert(recordId, Joi.string());
      Joi.assert(inputVersionId, Joi.string());
      Joi.assert(inputData, Joi.object().optional());
      Joi.assert(inputInfo, Joi.object().optional());
      const versionId = Number(inputVersionId);
      const data =
        typeof inputData === "object"
          ? inputData
          : { test: crypto.randomBytes(12).toString("hex") };
      const buffer = Buffer.from(JSON.stringify(data));
      const info =
        typeof inputInfo === "object"
          ? inputInfo
          : {
              info: crypto.randomBytes(12).toString("hex"),
            };
      const timestamp = {
        hash: {
          id: 1,
          value: sha256(buffer),
        },
        data: `0x${buffer.toString("hex")}`,
      };

      return {
        info: {
          title: "Append record version hashes",
          data: { data, info },
        },
        param: {
          recordId,
          versionId,
          hashAlgorithmIds: [timestamp.hash.id],
          hashValues: [timestamp.hash.value],
          timestampData: [timestamp.data],
          versionInfo: `0x${Buffer.from(JSON.stringify(info)).toString("hex")}`,
        },
      };
    }
    case "timestampHashes": {
      const [inputData] = inputs as UnknownObject[];
      Joi.assert(inputData, Joi.object().optional());
      const data =
        typeof inputData === "object"
          ? inputData
          : { test: crypto.randomBytes(12).toString("hex") };
      const buffer = Buffer.from(JSON.stringify(data));
      const timestamp = {
        hash: {
          id: 1,
          value: sha256(buffer),
        },
        data: `0x${buffer.toString("hex")}`,
      };
      const hashBuffer = fromHexString(sha256(timestamp.hash.value));
      const multihash = Multihash.encode(hashBuffer, "sha2-256", 32);
      const id = multibaseEncode("base64url", multihash);

      return {
        info: {
          title: "Timestamp hashes",
          data: { data, id },
        },
        param: {
          hashAlgorithmIds: [timestamp.hash.id],
          hashValues: [timestamp.hash.value],
          timestampData: [timestamp.data],
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
    default:
      throw new Error(`Invalid method '${method}'`);
  }
}

export default buildParamTimestamp;
