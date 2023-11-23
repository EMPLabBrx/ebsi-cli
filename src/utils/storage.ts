import crypto from "node:crypto";
import fs from "fs";
import Joi from "joi";
import FormData from "form-data";
import { UnknownObject } from "../interfaces/index.js";
import { httpCall } from "./http.js";
import { red } from "./print.js";

export function fileController(
  httpOpts: { headers: Record<string, unknown> },
  url: string,
  method: string,
  inputs: (string | UnknownObject)[]
): Promise<unknown> {
  switch (method) {
    case "insert": {
      const [inputFilename, inputMetadata] = inputs as [string, UnknownObject];
      Joi.assert(inputFilename, Joi.string().optional());
      Joi.assert(inputMetadata, Joi.object().optional());
      const filename =
        inputFilename || `test-${crypto.randomBytes(5).toString("hex")}.bin`;
      const filedata = inputFilename
        ? fs.readFileSync(filename)
        : crypto.randomBytes(50);
      const metadata =
        typeof inputMetadata === "object"
          ? inputMetadata
          : { test: crypto.randomBytes(12).toString("hex") };

      const form = new FormData();
      form.append("file", filedata, filename);
      form.append("metadata", JSON.stringify(metadata));
      const options = {
        headers: {
          post: form.getHeaders(),
          ...httpOpts.headers,
        },
      };
      return httpCall.post(`${url}/stores/distributed/files`, form, options);
    }
    case "patch": {
      const [hash, inputPatchOps] = inputs as [string, UnknownObject[]];
      Joi.assert(hash, Joi.string());
      Joi.assert(inputPatchOps, Joi.array().optional());
      const patchOps = Array.isArray(inputPatchOps)
        ? inputPatchOps
        : [
            {
              op: "replace",
              path: "/metadata",
              value: {
                test: crypto.randomBytes(12).toString("hex"),
              },
            },
          ];
      return httpCall.patch(
        `${url}/stores/distributed/files/${hash}`,
        patchOps,
        {
          headers: {
            "Content-Type": "application/json-patch+json",
            ...httpOpts.headers,
          },
        }
      );
    }
    case "delete": {
      const [hash] = inputs as string[];
      Joi.assert(hash, Joi.string());
      return httpCall.delete(
        `${url}/stores/distributed/files/${hash}`,
        httpOpts
      );
    }
    default:
      red(`Invalid method '${method}'`);
      return Promise.resolve(0);
  }
}

export function keyValueController(
  httpOpts: { headers: Record<string, unknown> },
  url: string,
  method: string,
  inputs: (string | UnknownObject)[]
): Promise<unknown> {
  switch (method) {
    case "insert":
    case "update": {
      const [key, value] = inputs as string[];
      Joi.assert(key, Joi.string().optional());
      Joi.assert(value, Joi.string().optional());
      const options = {
        headers: {
          "Content-Type": "text/plain",
          ...httpOpts.headers,
        },
      };
      return httpCall.put(
        `${url}/stores/distributed/key-values/${key}`,
        value,
        options
      );
    }
    case "delete": {
      const [hash] = inputs as string[];
      Joi.assert(hash, Joi.string());
      return httpCall.delete(
        `${url}/stores/distributed/key-values/${hash}`,
        httpOpts
      );
    }
    default:
      red(`Invalid method '${method}'`);
      return Promise.resolve(0);
  }
}

export function jsonrpcStorage(
  httpOpts: { headers: Record<string, unknown> },
  url: string,
  params: unknown[]
): Promise<unknown> {
  const body = {
    jsonrpc: "2.0",
    method: "cassandra_call",
    params,
    id: Math.ceil(Math.random() * 1000),
  };
  return httpCall.post(`${url}/stores/distributed/jsonrpc`, body, httpOpts);
}
