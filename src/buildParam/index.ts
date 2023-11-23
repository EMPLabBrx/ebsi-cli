import { Client } from "../utils/Client.js";
import { BuildParamResponse, UnknownObject } from "../interfaces/index.js";
import { buildParamDid } from "./did.js";
import { buildParamDidV3 } from "./didV3.js";
import { buildParamDidOld } from "./didOld.js";
import { buildParamTar } from "./tar.js";
import { buildParamTarV3 } from "./tarV3.js";
import { buildParamTimestamp } from "./timestamp.js";
import { buildParamTimestampV2 } from "./timestampV2.js";
import { buildParamTir } from "./tir.js";
import { buildParamTirV3 } from "./tirV3.js";
import { buildParamTsr } from "./tsr.js";
import { buildParamTsrV2 } from "./tsrV2.js";
import { buildParamTpr } from "./tpr.js";
import { buildParamTprV2 } from "./tprV2.js";

export async function buildParam(
  contract: string,
  method: string,
  client: Client,
  inputs: (string | UnknownObject)[]
): Promise<BuildParamResponse> {
  switch (contract) {
    case "timestamp":
      return buildParamTimestamp(method, client, inputs);
    case "timestamp-new":
      return buildParamTimestampV2(method, client, inputs);
    case "did":
      return buildParamDid(method, client, inputs);
    case "did-new":
      return buildParamDidV3(method, client, inputs);
    case "did-old":
      return buildParamDidOld(method, client, inputs);
    case "tar":
      return buildParamTar(method, client, inputs);
    case "tar-new":
      return buildParamTarV3(method, client, inputs);
    case "tir":
    case "tir-old":
      return buildParamTir(method, client, inputs);
    case "tir-new":
      return buildParamTirV3(method, client, inputs);
    case "tsr":
      return buildParamTsr(method, client, inputs);
    case "tsr-new":
      return buildParamTsrV2(method, client, inputs);
    case "tpr":
      return buildParamTpr(method, client, inputs);
    case "tpr-new":
      return buildParamTprV2(method, client, inputs);
    default:
      throw new Error(`Invalid contract '${contract}'`);
  }
}

export * from "./did.js";
export * from "./didOld.js";
export * from "./tar.js";
export * from "./tir.js";
export * from "./tsr.js";
export * from "./tpr.js";
export * from "./timestamp.js";
