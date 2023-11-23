import { randomUUID } from "node:crypto";
import { URLSearchParams } from "node:url";
import Joi from "joi";
import qs from "qs";
import { importJWK } from "jose";
import {
  Agent as SiopAgent,
  AkeResponse,
  verifyJwtTar,
} from "@cef-ebsi/siop-auth";
import { Agent as Oauth2Agent } from "@cef-ebsi/oauth2-auth";
import { httpCall, KeyPairJwk, red, yellow } from "../utils/index.js";
import { Context } from "../interfaces/context.js";
import { compute } from "./compute.js";

export async function authorisationGet(inputs: string[], context: Context) {
  const apiUrl = context.config.api["authorisation-new"].url;
  const response = await httpCall.get(
    `${apiUrl}${inputs.join("")}`,
    context.httpOpts
  );
  return response.data as unknown;
}

export async function authorisationToken(inputs: string[], context: Context) {
  const apiUrl = context.config.api["authorisation-new"].url;
  const [definitionId, vpJwt] = inputs;
  Joi.assert(
    definitionId,
    Joi.string().valid(
      "didr_invite_presentation",
      "didr_write_presentation",
      "tir_invite_presentation",
      "tir_write_presentation",
      "timestamp_write_presentation"
    )
  );

  const scopeByDefinition = {
    didr_invite_presentation: "openid didr_invite",
    didr_write_presentation: "openid didr_write",
    tir_invite_presentation: "openid tir_invite",
    tir_write_presentation: "openid tir_write",
    timestamp_write_presentation: "openid timestamp_write",
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

export async function authorisationAuth(inputs: string[], context: Context) {
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

export async function siopRequest(inputs: string[], context: Context) {
  const apiUrl = context.config.api["authorisation-new"].url;
  const response = await httpCall.post(
    `${apiUrl}/authentication-requests`,
    {
      scope: "openid did_authn",
    },
    context.httpOpts
  );
  const uri = response.data as string;
  const uriDecoded = qs.parse(uri.replace("openid://?", "")) as {
    client_id: string;
    request: string;
  };
  return {
    client_id: decodeURIComponent(uriDecoded.client_id),
    request: uriDecoded.request,
  };
}

export async function siopSession(inputs: string[], context: Context) {
  const [callbackUrl, inputAlg, verifiedClaims] = inputs;
  const alg = inputAlg || "ES256K";
  const nonce = randomUUID();

  const key = context.client.keys[alg] as KeyPairJwk;
  if (!key) throw new Error(`There is no key defined for alg ${alg}`);

  const agent = new SiopAgent({
    privateKey: await importJWK(key.privateKeyJwk, alg),
    alg,
    kid: key.kid,
    siopV2: true,
  });

  const { idToken } = await agent.createResponse({
    nonce,
    redirectUri: callbackUrl,
    claims: {
      encryption_key: key.publicKeyEncryptionJwk,
    },
    responseMode: "form_post",
    ...(verifiedClaims && {
      _vp_token: {
        presentation_submission: {
          id: randomUUID(),
          definition_id: randomUUID(),
          descriptor_map: [
            {
              id: randomUUID(),
              format: "jwt_vp",
              path: "$",
              path_nested: {
                id: "onboarding-input-id",
                format: "jwt_vc",
                path: "$.vp.verifiableCredential[0]",
              },
            },
          ],
        },
      },
    }),
  });

  const body = {
    id_token: idToken,
    ...(verifiedClaims && { vp_token: verifiedClaims }),
  };

  const responseSession = await httpCall.post<AkeResponse>(
    callbackUrl,
    body,
    context.httpOpts
  );

  return {
    alg,
    nonce,
    response: responseSession.data,
  };
}

export async function siop(inputs: string[], context: Context) {
  const [inputAlg] = inputs;
  const alg = inputAlg || "ES256K";

  console.log("==> authorisation-new siopRequest");
  const request = await siopRequest([], context);

  console.log(
    `==> compute verifyAuthenticationRequest ${JSON.stringify(request)}`
  );

  await verifyJwtTar(request.request, {
    trustedAppsRegistry: `${context.config.api["tar-new"].url}/apps`,
  });
  yellow("Authentication request OK");
  const callbackUrl = request.client_id;

  console.log(`==> authorisation-new siopSession ${callbackUrl} ${alg}`);
  const sessionResponse = await siopSession([callbackUrl, alg], context);

  console.log(
    `==> compute verifySessionResponse ${JSON.stringify(sessionResponse)}`
  );

  const key = context.client.keys[alg] as KeyPairJwk;
  if (!key)
    throw new Error(`There is no key defined for alg ${sessionResponse.alg}`);
  const accessToken = await SiopAgent.verifyAkeResponse(
    sessionResponse.response,
    {
      nonce: sessionResponse.nonce,
      privateEncryptionKeyJwk: key.privateKeyEncryptionJwk,
      trustedAppsRegistry: `${context.config.api["tar-new"].url}/apps`,
      alg: sessionResponse.alg,
    }
  );
  yellow(`Session Response OK. Access token: ${accessToken}`);
  return accessToken;
}

export async function oauth2Session(inputs: string[], context: Context) {
  const [audience] = inputs;
  const agent = new Oauth2Agent({
    privateKey: context.trustedApp.privateKey,
    name: context.trustedApp.name,
    trustedAppsRegistry: `${context.config.api["tar-new"].url}/apps`,
  });

  const nonce = randomUUID();
  const requestComponent = await agent.createRequest(audience, {
    nonce,
  });
  const apiUrl = context.config.api["authorisation-new"].url;
  const response = await httpCall.post<AkeResponse>(
    `${apiUrl}/oauth2-sessions`,
    requestComponent
  );

  const accessToken = await agent.verifyAkeResponse(response.data, { nonce });

  return accessToken;
}

export async function authorisationV4(
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

    case "auth": {
      return authorisationAuth(inputs, context);
    }

    // legacy endpoints

    case "siopRequest": {
      return siopRequest(inputs, context);
    }

    case "siopSession": {
      return siopSession(inputs, context);
    }

    case "siop": {
      return siop(inputs, context);
    }

    case "oauth2": {
      return oauth2Session(inputs, context);
    }

    default:
      red(`Invalid method '${method}'`);
      return 0;
  }
}

export default authorisationV4;
