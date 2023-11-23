import { randomUUID } from "node:crypto";
import { URLSearchParams } from "node:url";
import Joi from "joi";
import { httpCall, red } from "../utils/index.js";
import { Context } from "../interfaces/context.js";
import { compute } from "./compute.js";

async function authorisationGet(inputs: string[], context: Context) {
  const apiUrl = context.config.api.authorisation.url;
  const response = await httpCall.get(
    `${apiUrl}${inputs.join("")}`,
    context.httpOpts
  );
  return response.data as unknown;
}

async function authorisationToken(inputs: string[], context: Context) {
  const apiUrl = context.config.api.authorisation.url;
  const [definitionId, vpJwt] = inputs;
  Joi.assert(
    definitionId,
    Joi.string().valid(
      "didr_invite_presentation",
      "didr_write_presentation",
      "tir_invite_presentation",
      "tir_write_presentation"
    )
  );

  const scopeByDefinition = {
    didr_invite_presentation: "openid didr_invite",
    didr_write_presentation: "openid didr_write",
    tir_invite_presentation: "openid tir_invite",
    tir_write_presentation: "openid tir_write",
  };

  let descriptorMap = [];

  if (definitionId === "didr_invite_presentation") {
    descriptorMap = [
      {
        id: "didr_invite_credential",
        format: "jwt_vp",
        path: "$",
        path_nested: {
          id: "didr_invite_credential",
          format: "jwt_vc",
          path: "$.verifiableCredential[0]",
        },
      },
    ];
  } else if (definitionId === "tir_invite_presentation") {
    descriptorMap = [
      {
        id: "tir_invite_credential",
        format: "jwt_vp",
        path: "$",
        path_nested: {
          id: "tir_invite_credential",
          format: "jwt_vc",
          path: "$.verifiableCredential[0]",
        },
      },
    ];
  }

  const presentationSubmission = {
    id: randomUUID(),
    definition_id: definitionId,
    descriptor_map: descriptorMap,
  };
  const httpOpts = {
    headers: {
      "Content-Type": "application/x-www-form-urlencoded",
      ...(context.httpOpts && context.httpOpts.headers),
    },
  };
  const response = await httpCall.post(
    `${apiUrl}/token`,
    new URLSearchParams({
      grant_type: "vp_token",
      scope: scopeByDefinition[definitionId] as string,
      vp_token: vpJwt,
      presentation_submission: JSON.stringify(presentationSubmission),
    }).toString(),
    httpOpts
  );
  return response.data;
}

async function authorisationAuth(inputs: string[], context: Context) {
  const [definitionId, inputAlg, vc] = inputs;
  const alg = inputAlg || "ES256K";
  Joi.assert(alg, Joi.string().valid("ES256K", "ES256", "EdDSA", "RS256"));

  console.log("==> authorisation get /.well-known/openid-configuration");
  const openIdConfig = (await authorisationGet(
    ["/.well-known/openid-configuration"],
    context
  )) as { issuer: string };

  console.log(
    `==> compute createPresentationJwt ${vc || "empty"} ${alg} ${
      openIdConfig.issuer
    }`
  );
  const vpJwt = (await compute(
    "createPresentationJwt",
    [vc || "empty", alg, openIdConfig.issuer],
    context
  )) as string;

  console.log(`==> authorisation token ${definitionId} ${vpJwt}`);
  return authorisationToken([definitionId, vpJwt], context);
}

export async function authorisationV3(
  method: string,
  inputs: string[],
  context: Context
): Promise<unknown> {
  switch (method) {
    case "get": {
      return authorisationGet(inputs, context);
    }

    case "token": {
      return authorisationToken(inputs, context);
    }

    // TODO: how to name this method?
    case "auth": {
      return authorisationAuth(inputs, context);
    }

    default:
      red(`Invalid method '${method}'`);
      return 0;
  }
}

export default authorisationV3;
