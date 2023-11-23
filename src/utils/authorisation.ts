import { randomUUID } from "node:crypto";
import qs from "qs";
import { importJWK, JWK, SignJWT, base64url } from "jose";
import { Agent as SiopAgent, AkeResponse } from "@cef-ebsi/siop-auth";
import { Agent as Oauth2Agent } from "@cef-ebsi/oauth2-auth";
import { httpCall } from "./http.js";
import { TrustedApp } from "../interfaces/shared/utils.interface.js";
import { Config } from "../config.js";
import { Client, KeyPairJwk } from "./Client.js";

export function getPrivateKeyHex(privateKeyJwk: JWK): string {
  return Buffer.from(base64url.decode(privateKeyJwk.d)).toString("hex");
}

export async function createAuthenticationResponseJose(input: {
  alg: string;
  keyId: string;
  nonce: string;
  redirectUri: string;
  privateKeyJwk: JWK;
  publicKeyJwk: JWK;
  privateKeyEncryptionJwk?: JWK;
  publicKeyEncryptionJwk?: JWK;
  verifiedClaims?: string;
}): Promise<string> {
  const { alg, keyId, nonce, redirectUri, privateKeyJwk, publicKeyJwk } = input;
  const [did] = keyId.split("#");

  const privateKey = await importJWK(privateKeyJwk, alg);
  const payload = {
    sub: did,
    sub_jwk: publicKeyJwk,
    sub_did_verification_method_uri: keyId,
    nonce,
    claims: {
      ...(input.publicKeyEncryptionJwk && {
        encryption_key: input.publicKeyEncryptionJwk,
      }),
      ...(input.verifiedClaims && {
        verified_claims: input.verifiedClaims,
      }),
    },
  };

  const idToken = await new SignJWT(payload)
    .setProtectedHeader({
      alg,
      typ: "JWT",
      kid: did,
    })
    .setIssuedAt()
    .setIssuer("https://self-issued.me")
    .setAudience(redirectUri)
    .setExpirationTime("15s")
    .sign(privateKey);
  return idToken;
}

export async function oauth2SessionV2(
  app: TrustedApp,
  audience: string,
  config: Config
): Promise<string> {
  const agent = new Oauth2Agent({
    privateKey: app.privateKey,
    name: app.name,
    trustedAppsRegistry: `${config.api.tar.url}/apps`,
  });

  const nonce = randomUUID();
  const requestComponent = await agent.createRequest(audience, {
    nonce,
  });
  const apiUrl = config.api.authorisationV2.url;
  const response = await httpCall.post<AkeResponse>(
    `${apiUrl}/oauth2-sessions`,
    requestComponent
  );

  const accessToken = await agent.verifyAkeResponse(response.data, { nonce });

  return accessToken;
}

export async function siopRequestV2(
  config: Config,
  httpOpts: unknown
): Promise<{
  client_id: string;
  request: string;
}> {
  const apiUrl = config.api.authorisationV2.url;
  const response = await httpCall.post(
    `${apiUrl}/authentication-requests`,
    {
      scope: "openid did_authn",
    },
    httpOpts
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

export async function siopSessionV2(
  client: Client,
  callbackUrl: string,
  alg: string,
  httpOpts: unknown,
  verifiedClaims?: string
): Promise<{
  alg: string;
  nonce: string;
  response: AkeResponse;
}> {
  const nonce = randomUUID();

  const key = client.keys[alg] as KeyPairJwk;
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
    httpOpts
  );

  return {
    alg,
    nonce,
    response: responseSession.data,
  };
}
