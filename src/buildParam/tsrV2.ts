import crypto from "node:crypto";
import Joi from "joi";
import { JoiHexadecimal, computeSchemaId } from "../utils/index.js";
import {
  BuildParamResponse,
  UnknownObject,
} from "../interfaces/shared/index.js";
import { Client } from "../utils/Client.js";

export async function buildParamTsrV2(
  method: string,
  client: Client,
  inputs: (string | UnknownObject)[]
): Promise<BuildParamResponse> {
  switch (method) {
    case "insertSchema": {
      const [inputSchema, inputMetadata] = inputs as UnknownObject[];
      Joi.assert(inputSchema, Joi.object().optional());
      Joi.assert(inputMetadata, Joi.object().optional());

      const schema =
        typeof inputSchema === "object"
          ? inputSchema
          : {
              "@context": "https://ebsi.eu",
              type: "Schema",
              name: "example",
              data: crypto.randomBytes(16).toString("hex"),
            };
      const serializedSchema = JSON.stringify(schema);
      const serializedSchemaBuffer = Buffer.from(serializedSchema);

      const metadata =
        typeof inputMetadata === "object"
          ? inputMetadata
          : {
              meta: "value",
              data: crypto.randomBytes(16).toString("hex"),
              validFrom: new Date(Date.now() - 60 * 1000).toISOString(), // -1 minute
              validTo: new Date(Date.now() + 5 * 60 * 1000).toISOString(), // +5 minutes
            };
      const serializedMetadata = JSON.stringify(metadata);
      const serializedMetadataBuffer = Buffer.from(serializedMetadata);
      const schemaId = await computeSchemaId(schema, "base16");

      return {
        info: {
          title: `Schema Id ${schemaId}`,
          data: { schema, metadata },
        },
        param: {
          schemaId,
          schema: `0x${serializedSchemaBuffer.toString("hex")}`,
          metadata: `0x${serializedMetadataBuffer.toString("hex")}`,
        },
      };
    }
    case "updateSchema": {
      const [schemaId, inputSchema, inputMetadata] = inputs as [
        string,
        UnknownObject,
        UnknownObject
      ];
      Joi.assert(schemaId, JoiHexadecimal);
      Joi.assert(inputSchema, Joi.object().optional());
      Joi.assert(inputMetadata, Joi.object().optional());

      const schema =
        typeof inputSchema === "object"
          ? inputSchema
          : {
              "@context": "https://ebsi.eu",
              type: "Schema",
              name: "example",
              data: crypto.randomBytes(16).toString("hex"),
            };
      const serializedSchema = JSON.stringify(schema);
      const serializedSchemaBuffer = Buffer.from(serializedSchema);

      const metadata =
        typeof inputMetadata === "object"
          ? inputMetadata
          : {
              meta: "value",
              data: crypto.randomBytes(16).toString("hex"),
              validFrom: new Date(Date.now() - 60 * 1000).toISOString(), // -1 minute
              validTo: new Date(Date.now() + 5 * 60 * 1000).toISOString(), // +5 minutes
            };
      const serializedMetadata = JSON.stringify(metadata);
      const serializedMetadataBuffer = Buffer.from(serializedMetadata);

      return {
        info: {
          title: `Schema Id ${schemaId}`,
          data: { schema, metadata },
        },
        param: {
          schemaId,
          schema: `0x${serializedSchemaBuffer.toString("hex")}`,
          metadata: `0x${serializedMetadataBuffer.toString("hex")}`,
        },
      };
    }
    case "updateMetadata": {
      const [schemaRevisionId, inputMetadata] = inputs as [
        string,
        UnknownObject
      ];
      Joi.assert(schemaRevisionId, Joi.string());
      Joi.assert(inputMetadata, Joi.object().optional());

      const metadata =
        typeof inputMetadata === "object"
          ? inputMetadata
          : {
              meta: "value",
              data: crypto.randomBytes(16).toString("hex"),
              validFrom: new Date(Date.now() - 60 * 1000).toISOString(), // -1 minute
              validTo: new Date(Date.now() + 5 * 60 * 1000).toISOString(), // +5 minutes
            };
      const serializedMetadata = JSON.stringify(metadata);
      const serializedMetadataBuffer = Buffer.from(serializedMetadata);
      return {
        info: {
          title: `Update metadata ${schemaRevisionId}`,
          data: metadata,
        },
        param: {
          schemaRevisionId,
          metadata: `0x${serializedMetadataBuffer.toString("hex")}`,
        },
      };
    }
    default:
      throw new Error(`Invalid method '${method}'`);
  }
}

export default buildParamTsrV2;
