import crypto from "node:crypto";
import Joi from "joi";
import {
  BuildParamResponse,
  UnknownObject,
} from "../interfaces/shared/index.js";
import { JoiHexadecimal, prefixWith0x } from "../utils/index.js";
import { Client } from "../utils/Client.js";

const issuerTypes = ["undefined", "roottao", "tao", "ti", "revoked"];

function getBufferAttribute(
  attribute: UnknownObject | string | Buffer
): Buffer {
  if (attribute instanceof Buffer) return attribute;

  let buffer: Buffer;
  if (typeof attribute === "object") {
    // json attribute
    buffer = Buffer.from(JSON.stringify(attribute));
  } else if (typeof attribute === "string") {
    if (/^(0x|0X)?[a-fA-F0-9]+$/g.test(attribute)) {
      // buffer attribute defined in hex string
      buffer = Buffer.from(attribute.replace("0x", ""), "hex");
    } else {
      // jwt attribute
      buffer = Buffer.from(attribute);
    }
  } else {
    throw new Error(`invalid type for attribute: ${typeof attribute}`);
  }
  return buffer;
}

export function buildParamTir(
  method: string,
  client: Client,
  inputs: (string | UnknownObject | Buffer)[]
): BuildParamResponse {
  switch (method) {
    case "setRegistryAddresses": {
      return {
        info: { title: "initialization", data: method },
        param: {},
      };
    }

    case "insertIssuer": {
      const [
        did,
        attribute,
        inputIssuerType,
        inputTaoDid,
        inputTaoAttributeId,
      ] = inputs as [string, UnknownObject | string, string, string, string];
      Joi.assert(did, Joi.string());
      Joi.assert(inputIssuerType, Joi.string().valid(...issuerTypes));
      Joi.assert(inputTaoDid, Joi.string().optional());
      Joi.assert(inputTaoAttributeId, Joi.string().optional());

      const buffer = getBufferAttribute(attribute);
      const attributeData = `0x${buffer.toString("hex")}`;
      const issuerType = issuerTypes.findIndex((i) => i === inputIssuerType);
      let taoDid = inputTaoDid;
      let taoAttributeId = inputTaoAttributeId;

      if (inputIssuerType === "roottao") {
        if (!taoDid) taoDid = did;
        if (!taoAttributeId) taoAttributeId = `0x${"0".repeat(64)}`;
      }

      return {
        info: { title: `Issuer ${did}`, data: attributeData },
        param: {
          did,
          attributeData,
          issuerType,
          taoDid,
          taoAttributeId: prefixWith0x(taoAttributeId),
        },
      };
    }

    case "updateIssuer": {
      const [
        did,
        attribute,
        inputIssuerType,
        taoDid,
        taoAttributeId,
        prevAttributeHash,
      ] = inputs as [
        string,
        UnknownObject | string,
        string,
        string,
        string,
        string
      ];
      Joi.assert(did, Joi.string());
      Joi.assert(inputIssuerType, Joi.string().valid(...issuerTypes));
      Joi.assert(taoDid, Joi.string());
      Joi.assert(taoAttributeId, Joi.string());
      Joi.assert(prevAttributeHash, JoiHexadecimal.optional());

      const buffer = getBufferAttribute(attribute);
      const attributeData = `0x${buffer.toString("hex")}`;
      const issuerType = issuerTypes.findIndex((i) => i === inputIssuerType);

      const updateAttribute = !!prevAttributeHash;
      return {
        info: { title: `Update Issuer ${did}`, data: attributeData },
        param: {
          did,
          attributeData,
          ...(updateAttribute && {
            prevAttributeHash: prefixWith0x(prevAttributeHash),
          }),
          issuerType,
          taoDid,
          taoAttributeId: prefixWith0x(taoAttributeId),
        },
        method: updateAttribute
          ? "updateIssuer(string,bytes,bytes32,uint8,string,bytes32)"
          : "updateIssuer(string,bytes,uint8,string,bytes32)",
      };
    }

    case "setAttributeMetadata": {
      const [
        did,
        attributeId,
        inputIssuerType,
        inputTaoDid,
        inputTaoAttributeId,
      ] = inputs as string[];
      Joi.assert(did, Joi.string());
      Joi.assert(inputIssuerType, Joi.string().valid(...issuerTypes));
      Joi.assert(inputTaoDid, Joi.string().optional());
      Joi.assert(inputTaoAttributeId, Joi.string().optional());

      const issuerType = issuerTypes.findIndex((i) => i === inputIssuerType);
      let taoDid = inputTaoDid;
      let taoAttributeId = inputTaoAttributeId;

      if (inputIssuerType === "roottao") {
        if (!taoDid) taoDid = did;
        if (!taoAttributeId) taoAttributeId = `0x${"0".repeat(64)}`;
      }

      return {
        info: {
          title: `Issuer ${did}`,
          data: { attributeId, issuerType: inputIssuerType },
        },
        param: {
          did,
          attributeId: prefixWith0x(attributeId),
          issuerType,
          taoDid,
          taoAttributeId: prefixWith0x(taoAttributeId),
        },
      };
    }

    case "setAttributeData": {
      const [did, attributeId, attribute] = inputs as [
        string,
        string,
        UnknownObject | string
      ];
      Joi.assert(did, Joi.string());
      Joi.assert(attributeId, Joi.string());

      const buffer = getBufferAttribute(attribute);
      const attributeData = `0x${buffer.toString("hex")}`;

      return {
        info: { title: `Issuer ${did}`, data: { attributeId } },
        param: {
          did,
          attributeId: prefixWith0x(attributeId),
          attributeData,
        },
      };
    }

    case "addIssuerProxy": {
      const [did, inputProxyData] = inputs as [string, UnknownObject];
      Joi.assert(did, Joi.string());

      const proxyData = JSON.stringify(inputProxyData);

      return {
        info: { title: `Proxy data for issuer ${did}`, data: proxyData },
        param: {
          did,
          proxyData,
        },
      };
    }

    case "updateIssuerProxy": {
      const [did, proxyId, inputProxyData] = inputs as [
        string,
        string,
        UnknownObject
      ];
      Joi.assert(did, Joi.string());
      Joi.assert(proxyId, Joi.string());

      const proxyData = JSON.stringify(inputProxyData);

      return {
        info: { title: `Proxy data for issuer ${did}`, data: proxyData },
        param: {
          did,
          proxyId,
          proxyData,
        },
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

    default:
      throw new Error(`Invalid method '${method}'`);
  }
}

export default buildParamTir;
