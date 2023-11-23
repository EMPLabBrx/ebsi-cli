import Joi from "joi";
import {
  BuildParamResponse,
  UnknownObject,
} from "../interfaces/shared/index.js";
import { prefixWith0x } from "../utils/index.js";
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

export function buildParamTirV3(
  method: string,
  client: Client,
  inputs: (string | UnknownObject | Buffer)[]
): BuildParamResponse {
  switch (method) {
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

    default:
      throw new Error(`Invalid method '${method}'`);
  }
}

export default buildParamTirV3;
