import { randomUUID, randomBytes, createHash } from "node:crypto";
import { URLSearchParams } from "node:url";
import Joi from "joi";
import qs from "qs";
import { base64url } from "multiformats/bases/base64";
import { importJWK, SignJWT } from "jose";
import { compute, getUserPin } from "./compute.js";
import { httpCall, red } from "../utils/index.js";
import { Context } from "../interfaces/context.js";
import { Alg, UnknownObject } from "../interfaces/index.js";

interface OpenIdCredentialIssuer {
  credential_issuer: string;
  authorization_server: string;
  deferred_credential_endpoint: string;
}

interface OpenIdConfiguration {
  redirect_uris: string[];
  issuer: string;
  authorization_endpoint: string;
  token_endpoint: string;
  jwks_uri: string;
}

type CredentialOffer = {
  credential_offer?: string;
  credential_offer_uri?: string;
};

type CredentialOfferPayload = {
  credential_issuer: string;
  credentials: {
    format: "jwt_vc";
    types: string[];
    trust_framework: {
      name: string;
      type: string;
      uri: string;
    };
  }[];
  grants: {
    authorization_code?: {
      issuer_state?: string;
    };
    "urn:ietf:params:oauth:grant-type:pre-authorized_code"?: {
      "pre-authorized_code": string;
      user_pin_required: boolean;
    };
  };
};

function stringify(obj: unknown, fields: string[]): string {
  if (typeof obj !== "object") throw new Error("not an object");
  const newObj = {};
  fields.forEach((f) => {
    if (obj[f]) newObj[f] = obj[f] as unknown;
  });
  return JSON.stringify(newObj);
}

export async function conformanceGet(inputs: string[], context: Context) {
  const apiUrl = context.config.api["conformance-new"].url;
  const urlPath = inputs.join("");
  const url = urlPath.startsWith("http") ? urlPath : `${apiUrl}${urlPath}`;
  const response = await httpCall.get(url, context.httpOpts);
  return response.data as unknown;
}

export async function clientMockInitiate(context: Context) {
  const apiUrl = context.config.api["conformance-new"].url;
  const { accreditationUrl, proxyId, issuerState } = context.rtVars.user as {
    accreditationUrl: string;
    proxyId: string;
    issuerState: string;
  };
  const response = await httpCall.post(`${apiUrl}/client-mock/initiate`, {
    did: context.client.did,
    keys: Object.keys(context.client.keys).map((keyName: Alg) => {
      const key = context.client.keys[keyName];
      return {
        ...key.privateKeyJwk,
        kid: key.id,
      };
    }),
    ...(accreditationUrl && { attributeUrl: accreditationUrl }),
    ...(proxyId && { proxyId }),
    ...(issuerState && { issuerState }),
  });
  context.client.clientId = `${apiUrl}/client-mock/${context.client.did}`;
  (context.rtVars.user as { clientId: string }).clientId =
    context.client.clientId;
  return response.data;
}

export async function clientMockUpdateList(inputs: string[], context: Context) {
  const [statusIndex, statusListIndex, value] = inputs;
  const apiUrl = context.config.api["conformance-new"].url;
  const response = await httpCall.post(`${apiUrl}/client-mock/updateList`, {
    did: context.client.did,
    id: statusIndex,
    position: Number(statusListIndex),
    value: Number(value),
  });
  return response.data;
}

export async function authMockAuthorize(inputs: unknown, context: Context) {
  const [
    openIdCredentialIssuer,
    openIdConfiguration,
    requestedTypes,
    inputAlg,
    codeVerifier,
    issuerState,
  ] = inputs as [
    OpenIdCredentialIssuer,
    OpenIdConfiguration,
    string[],
    string,
    string,
    string
  ];
  const alg = (inputAlg as Alg) || "ES256";

  Joi.assert(requestedTypes, Joi.array());
  Joi.assert(alg, Joi.string().valid("ES256K", "ES256", "EdDSA", "RS256"));

  const isPKCEChallenge = !!codeVerifier;

  const authorizationServer =
    openIdCredentialIssuer.authorization_server ??
    openIdCredentialIssuer.credential_issuer;

  const clientId =
    context.client.didVersion === 1
      ? context.client.clientId
      : context.client.did;

  let codeChallenge = "";
  if (isPKCEChallenge) {
    codeChallenge = base64url.baseEncode(
      createHash("sha256").update(codeVerifier).digest()
    );
  }

  const clientMetadata = isPKCEChallenge
    ? {
        authorization_endpoint: "openid:",
      }
    : {
        redirect_uris: [`${context.client.clientId}/code-cb`],
        jwks_uri: `${context.client.clientId}/jwks`,
        authorization_endpoint: `${context.client.clientId}/authorize`,
      };

  const authorizationDetails = [
    {
      type: "openid_credential",
      format: "jwt_vc",
      locations: [openIdCredentialIssuer.credential_issuer],
      types: requestedTypes,
    },
  ];

  const queryParams = {
    scope: "openid",
    client_id: clientId,
    client_metadata: JSON.stringify(clientMetadata),
    redirect_uri: isPKCEChallenge
      ? "openid://callback"
      : `${context.client.clientId}/code-cb`,
    response_type: "code",
    state: randomUUID(),
    ...(isPKCEChallenge && {
      code_challenge: codeChallenge,
      code_challenge_method: "S256",
    }),
    ...(issuerState && { issuer_state: issuerState }),
    authorization_details: JSON.stringify(authorizationDetails),
  };

  const jwtPayload = {
    ...queryParams,
    client_metadata: clientMetadata,
    authorization_details: authorizationDetails,
  };

  const clientPrivateKey = await importJWK(
    context.client.keys[alg].privateKeyJwk,
    alg
  );
  const requestParam = await new SignJWT(jwtPayload)
    .setProtectedHeader({
      typ: "JWT",
      alg,
      kid: isPKCEChallenge
        ? context.client.keys[alg].kid
        : context.client.keys[alg].id,
    })
    .setIssuer(clientId)
    .setAudience(authorizationServer)
    .sign(clientPrivateKey);

  const responseAuthorize = await httpCall.get(
    `${openIdConfiguration.authorization_endpoint}?${new URLSearchParams({
      ...queryParams,
      request: requestParam,
    } as unknown as URLSearchParams).toString()}`
  );

  const { location } = responseAuthorize.headers as { [x: string]: string };
  const locationUrl = new URL(location);
  if (locationUrl.searchParams.get("error"))
    throw new Error(locationUrl.searchParams.toString());
  const responseQueryParams = qs.parse(locationUrl.search.substring(1));

  return responseQueryParams;
}

export async function authMockDirectPostIdToken(
  inputs: unknown,
  context: Context
) {
  const [openIdCredentialIssuer, openIdConfiguration, issuerRequest, inputAlg] =
    inputs as [
      OpenIdCredentialIssuer,
      OpenIdConfiguration,
      { state: string; nonce: string },
      string
    ];
  const alg = (inputAlg as Alg) || "ES256";

  Joi.assert(alg, Joi.string().valid("ES256K", "ES256", "EdDSA", "RS256"));

  const authorizationServer =
    openIdCredentialIssuer.authorization_server ??
    openIdCredentialIssuer.credential_issuer;

  const { state, nonce } = issuerRequest;
  const clientPrivateKey = await importJWK(
    context.client.keys[alg].privateKeyJwk,
    alg
  );
  const idTokenDirectPost = await new SignJWT({
    nonce,
    sub: context.client.did,
  })
    .setProtectedHeader({
      typ: "JWT",
      alg,
      kid: context.client.keys[alg].kid,
    })
    .setIssuer(context.client.did)
    .setAudience(authorizationServer)
    .setIssuedAt()
    .setExpirationTime("5m")
    .sign(clientPrivateKey);

  const responseDirectPost = await httpCall.post(
    openIdConfiguration.redirect_uris[0],
    new URLSearchParams({
      id_token: idTokenDirectPost,
      state,
    }).toString(),
    {
      headers: {
        "content-type": "application/x-www-form-urlencoded",
      },
    }
  );

  const { location } = responseDirectPost.headers as { [x: string]: string };
  const locationUrl = new URL(location);
  if (locationUrl.searchParams.get("error"))
    throw new Error(locationUrl.searchParams.toString());
  const responseQueryParams = qs.parse(locationUrl.search.substring(1));

  return responseQueryParams;
}

export async function authMockDirectPostVpToken(inputs: unknown[]) {
  const [openIdConfiguration, issuerRequest, vpJwt, type] = inputs as [
    OpenIdConfiguration,
    { state: string; nonce: string },
    string,
    string
  ];

  const { state } = issuerRequest;
  const presentationSubmission =
    type === "holder"
      ? {
          id: randomUUID(),
          definition_id: "holder-wallet-qualification-presentation",
          descriptor_map: [
            {
              id: "same-device-authorised-in-time-credential",
              path: "$",
              format: "jwt_vp",
              path_nested: {
                id: "same-device-authorised-in-time-credential",
                format: "jwt_vc",
                path: "$.verifiableCredential[0]",
              },
            },
            {
              id: "cross-device-authorised-in-time-credential",
              path: "$",
              format: "jwt_vp",
              path_nested: {
                id: "cross-device-authorised-in-time-credential",
                format: "jwt_vc",
                path: "$.verifiableCredential[1]",
              },
            },
            {
              id: "same-device-authorised-deferred-credential",
              path: "$",
              format: "jwt_vp",
              path_nested: {
                id: "same-device-authorised-deferred-credential",
                format: "jwt_vc",
                path: "$.verifiableCredential[2]",
              },
            },
            {
              id: "cross-device-authorised-deferred-credential",
              path: "$",
              format: "jwt_vp",
              path_nested: {
                id: "cross-device-authorised-deferred-credential",
                format: "jwt_vc",
                path: "$.verifiableCredential[3]",
              },
            },
            {
              id: "same-device-pre-authorised-in-time-credential",
              path: "$",
              format: "jwt_vp",
              path_nested: {
                id: "same-device-pre-authorised-in-time-credential",
                format: "jwt_vc",
                path: "$.verifiableCredential[4]",
              },
            },
            {
              id: "cross-device-pre-authorised-in-time-credential",
              path: "$",
              format: "jwt_vp",
              path_nested: {
                id: "cross-device-pre-authorised-in-time-credential",
                format: "jwt_vc",
                path: "$.verifiableCredential[5]",
              },
            },
            {
              id: "same-device-pre-authorised-deferred-credential",
              path: "$",
              format: "jwt_vp",
              path_nested: {
                id: "same-device-pre-authorised-deferred-credential",
                format: "jwt_vc",
                path: "$.verifiableCredential[6]",
              },
            },
            {
              id: "cross-device-pre-authorised-deferred-credential",
              path: "$",
              format: "jwt_vp",
              path_nested: {
                id: "cross-device-pre-authorised-deferred-credential",
                format: "jwt_vc",
                path: "$.verifiableCredential[7]",
              },
            },
          ],
        }
      : {
          id: randomUUID(),
          definition_id: "va-to-onboard-presentation",
          descriptor_map: [
            {
              id: "verifiable-authorisation-to-onboard",
              format: "jwt_vp",
              path: "$",
              path_nested: {
                id: "verifiable-authorisation-to-onboard",
                format: "jwt_vc",
                path: "$.verifiableCredential[0]",
              },
            },
          ],
        };
  const responseDirectPost = await httpCall.post(
    openIdConfiguration.redirect_uris[0],
    new URLSearchParams({
      vp_token: vpJwt,
      state,
      presentation_submission: JSON.stringify(presentationSubmission),
    }).toString(),
    {
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
      },
    }
  );

  const { location } = responseDirectPost.headers as { [x: string]: string };
  const locationUrl = new URL(location);
  if (locationUrl.searchParams.get("error"))
    throw new Error(locationUrl.searchParams.toString());
  const responseQueryParams = qs.parse(locationUrl.search.substring(1));

  return responseQueryParams;
}

export async function authMockToken(inputs: unknown, context: Context) {
  const [
    openIdCredentialIssuer,
    openIdConfiguration,
    code,
    inputAlg,
    codeVerifier,
    type,
  ] = inputs as [
    OpenIdCredentialIssuer,
    OpenIdConfiguration,
    string,
    string,
    string,
    string
  ];
  const alg = (inputAlg as Alg) || "ES256";

  const isPKCEChallenge = !!codeVerifier;

  const authorizationServer =
    openIdCredentialIssuer.authorization_server ??
    openIdCredentialIssuer.credential_issuer;

  let queryParams: Record<string, unknown>;
  if (type === "preAuthorised") {
    queryParams = {
      grant_type: "urn:ietf:params:oauth:grant-type:pre-authorized_code",
      "pre-authorized_code": code,
      user_pin: getUserPin(context.client.did),
    };
  } else {
    queryParams = {
      grant_type: "authorization_code",
      code,
      client_id: isPKCEChallenge ? context.client.did : context.client.clientId,
      ...(!isPKCEChallenge && {
        client_assertion_type:
          "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
      }),
      ...(isPKCEChallenge && {
        code_verifier: codeVerifier,
      }),
    };
  }

  const jwtPayload = {
    ...queryParams,
  };

  const clientPrivateKey = await importJWK(
    context.client.keys[alg].privateKeyJwk,
    alg
  );
  const clientAssertion = await new SignJWT(jwtPayload)
    .setProtectedHeader({
      typ: "JWT",
      alg,
      kid: context.client.keys[alg].id,
    })
    .setIssuer(context.client.clientId)
    .setAudience(authorizationServer)
    .setSubject(context.client.clientId)
    .setIssuedAt()
    .setExpirationTime("5m")
    .sign(clientPrivateKey);

  const responseToken = await httpCall.post(
    openIdConfiguration.token_endpoint,
    new URLSearchParams({
      ...queryParams,
      client_assertion: clientAssertion,
    }).toString(),
    {
      headers: {
        "content-type": "application/x-www-form-urlencoded",
      },
    }
  );
  return responseToken.data;
}

export async function issuerMockCredential(inputs: unknown, context: Context) {
  const [openIdCredentialIssuer, nonce, requestedTypes, inputAlg] = inputs as [
    OpenIdCredentialIssuer,
    string,
    string[],
    string
  ];
  const alg = (inputAlg as Alg) || "ES256";
  const clientId =
    context.client.didVersion === 1
      ? context.client.clientId
      : context.client.did;

  const clientPrivateKey = await importJWK(
    context.client.keys[alg].privateKeyJwk,
    alg
  );
  const proofJwt = await new SignJWT({ nonce })
    .setProtectedHeader({
      typ: "openid4vci-proof+jwt",
      alg,
      kid: context.client.keys[alg].kid,
    })
    .setIssuer(clientId)
    .setAudience(openIdCredentialIssuer.credential_issuer)
    .setIssuedAt()
    .setExpirationTime("5m")
    .sign(clientPrivateKey);

  const responseCredential = await httpCall.post(
    `${openIdCredentialIssuer.credential_issuer}/credential`,
    {
      types: requestedTypes,
      format: "jwt_vc",
      proof: {
        proof_type: "jwt",
        jwt: proofJwt,
      },
    },
    context.httpOpts
  );
  return responseCredential.data;
}

export async function issuerMockDeferred(inputs: unknown[]) {
  const [openIdCredentialIssuer, acceptanceToken] = inputs as [
    OpenIdCredentialIssuer,
    string
  ];
  const response = await httpCall.post(
    openIdCredentialIssuer.deferred_credential_endpoint,
    undefined,
    {
      headers: {
        authorization: `Bearer ${acceptanceToken}`,
      },
    }
  );
  return response.data;
}

export async function issuerMockInitiateCredentialOffer(
  inputs: unknown,
  context: Context
) {
  const [initiateCredentialOfferEndpoint, credentialType] = inputs as [
    string,
    string
  ];

  const requestParams = {
    credential_type: credentialType,
    credential_offer_endpoint: "openid-credential-offer://",
    client_id: context.client.did,
  };

  let response = await httpCall.get(
    `${initiateCredentialOfferEndpoint}?${qs.stringify(requestParams)}`
  );

  let search: string;
  if (credentialType.startsWith("CTWalletSame")) {
    search = new URL((response.headers as { location: string }).location)
      .search;
  } else {
    search = new URL(response.data as string).search;
  }

  const parsedCredentialOffer = qs.parse(search.slice(1)) as CredentialOffer;

  if (parsedCredentialOffer.credential_offer_uri) {
    response = await httpCall.get(parsedCredentialOffer.credential_offer_uri);
    return response.data as CredentialOfferPayload;
  }

  return qs.parse(
    parsedCredentialOffer.credential_offer
  ) as unknown as CredentialOfferPayload;
}

export async function getCredential(inputs: unknown, context: Context) {
  const [type, inputAlg, vc, inputIssuer] = inputs as [
    string,
    string,
    string,
    string
  ];
  const alg = (inputAlg as Alg) || "ES256";
  const openIdCredentialIssuerUrl = inputIssuer
    ? `/client-mock/${inputIssuer}/.well-known/openid-credential-issuer`
    : "/issuer-mock/.well-known/openid-credential-issuer";

  let requestedTypes: string[];
  switch (type) {
    case "onboard": {
      requestedTypes = [
        "VerifiableCredential",
        "VerifiableAttestation",
        "VerifiableAuthorisationToOnboard",
      ];
      break;
    }
    case "ti": {
      requestedTypes = [
        "VerifiableCredential",
        "VerifiableAttestation",
        "VerifiableAccreditation",
        "VerifiableAccreditationToAttest",
      ];
      break;
    }
    case "tao": {
      requestedTypes = [
        "VerifiableCredential",
        "VerifiableAttestation",
        "VerifiableAccreditation",
        "VerifiableAccreditationToAccredit",
      ];
      break;
    }
    case "roottao": {
      requestedTypes = [
        "VerifiableCredential",
        "VerifiableAttestation",
        "VerifiableAuthorisationForTrustChain",
      ];
      break;
    }
    case "ctrevocable": {
      requestedTypes = [
        "VerifiableCredential",
        "VerifiableAttestation",
        "CTRevocable",
      ];
      break;
    }
    case "qualification": {
      requestedTypes = [
        "VerifiableCredential",
        "VerifiableAttestation",
        "CTAAQualificationCredential",
      ];
      break;
    }
    default:
      throw new Error(`type ${type} is not supported`);
  }

  // conformance-new clientMockInitiate
  console.log("==> conformance-new clientMockInitiate");
  await clientMockInitiate(context);

  // opIssuer: conformance-new get /issuer-mock/.well-known/openid-credential-issuer
  console.log(`==> conformance-new get ${openIdCredentialIssuerUrl}`);
  const opIssuer = (await conformanceGet(
    [openIdCredentialIssuerUrl],
    context
  )) as OpenIdCredentialIssuer;

  const authorizationServer =
    opIssuer.authorization_server ?? opIssuer.credential_issuer;

  // opConf: conformance-new get opIssuer.authorization_server /.well-known/openid-configuration
  console.log(
    `==> conformance-new get ${authorizationServer}/.well-known/openid-configuration`
  );
  const opConf = (await conformanceGet(
    [authorizationServer, "/.well-known/openid-configuration"],
    context
  )) as OpenIdConfiguration;

  // respAuthorize: conformance-new authMockAuthorize opIssuer opConf requestedTypes ES256
  console.log(
    `==> conformance-new authMockAuthorize ${stringify(opIssuer, [
      "authorization_server",
      "credential_issuer",
    ])} ${stringify(opConf, ["authorization_endpoint"])} ${JSON.stringify(
      requestedTypes
    )} ${alg}`
  );
  const respAuthorize = await authMockAuthorize(
    [opIssuer, opConf, requestedTypes, alg],
    context
  );

  let code: string;
  if (type === "roottao") {
    // vpJwt: compute createPresentationJwt vc alg opConf.issuer
    console.log(
      `==> compute createPresentationJwt ${vc || "empty"} ${alg} ${
        opConf.issuer
      }`
    );
    const vpJwt = (await compute(
      "createPresentationJwt",
      [vc || "empty", alg, opConf.issuer],
      context
    )) as string;

    // respDirectPost: conformance-new authMockDirectPostVpToken opIssuer opConf respAuthorize ES256
    console.log(
      `==> conformance-new authMockDirectPostVpToken ${stringify(opConf, [
        "redirect_uris",
      ])} ${JSON.stringify(respAuthorize)} ${vpJwt}`
    );
    const respDirectPost = (await authMockDirectPostVpToken([
      opConf,
      respAuthorize,
      vpJwt,
    ])) as { code: string };
    code = respDirectPost.code;
  } else {
    // respDirectPost: conformance-new authMockDirectPostIdToken opIssuer opConf respAuthorize ES256
    console.log(
      `==> conformance-new authMockDirectPostIdToken ${stringify(opIssuer, [
        "authorization_server",
        "credential_issuer",
      ])} ${stringify(opConf, ["redirect_uris"])} ${JSON.stringify(
        respAuthorize
      )} ${alg}`
    );
    const respDirectPost = (await authMockDirectPostIdToken(
      [opIssuer, opConf, respAuthorize, alg],
      context
    )) as { code: string };
    code = respDirectPost.code;
  }

  // resToken: conformance-new authMockToken opIssuer opConf respDirectPost.code ES256
  console.log(
    `==> conformance-new authMockToken ${stringify(opIssuer, [
      "authorization_server",
      "credential_issuer",
    ])} ${stringify(opConf, ["token_endpoint"])} ${code} ${alg}`
  );
  const respToken = (await authMockToken(
    [opIssuer, opConf, code, alg],
    context
  )) as { access_token: string; c_nonce: string };

  // using token resToken.access_token
  console.log(`==> using token ${respToken.access_token}`);
  context.httpOpts = {
    headers: {
      authorization: `Bearer ${respToken.access_token}`,
    },
  };

  // resCredential: conformance-new issuerMockCredential opIssuer resToken.c_nonce requestedTypes ES256
  console.log(
    `==> conformance-new issuerMockCredential ${stringify(opIssuer, [
      "credential_issuer",
    ])} ${respToken.c_nonce} ${JSON.stringify(requestedTypes)} ${alg}`
  );
  const respCredential = (await issuerMockCredential(
    [opIssuer, respToken.c_nonce, requestedTypes, alg],
    context
  )) as { credential: string; acceptance_token: string };

  let credential: string;
  if (type === "roottao") {
    console.log(`waiting 5.5 seconds...`);
    await new Promise((r) => {
      setTimeout(r, 5500);
    });
    // respDeferred: conformance-new issuerMockDeferred respDirectPost.acceptance_token
    console.log(
      `==> conformance-new issuerMockDeferred ${stringify(opIssuer, [
        "deferred_credential_endpoint",
      ])} ${respCredential.acceptance_token}`
    );
    const respDeferred = (await issuerMockDeferred([
      opIssuer,
      respCredential.acceptance_token,
    ])) as { credential: string };
    credential = respDeferred.credential;
  } else {
    credential = respCredential.credential;
  }

  // decodedCredential: compute decodeJWT resCredential.credential
  console.log(`==> compute decodeJWT ${credential}`);
  const decodedCredential = (await compute(
    "decodeJWT",
    [credential],
    context
  )) as {
    payload: {
      vc?: { credentialSubject?: { reservedAttributeId?: string } };
    };
  };

  let reservedAttributeId = "";
  if (
    decodedCredential.payload.vc &&
    decodedCredential.payload.vc.credentialSubject &&
    decodedCredential.payload.vc.credentialSubject.reservedAttributeId
  ) {
    reservedAttributeId =
      decodedCredential.payload.vc.credentialSubject.reservedAttributeId;
  }

  return {
    vc: credential,
    reservedAttributeId,
  };
}

export async function holder(inputs: unknown, context: Context) {
  const apiUrl = context.config.api["conformance-new"].url;

  const [
    credentialType,
    communicationType,
    inputAlg,
    vc,
    typeCredentialOffer,
    inputIssuer,
  ] = inputs as [string, string, string, string, string, string];
  const alg = (inputAlg as Alg) || "ES256";

  const codeVerifier = randomBytes(50).toString("base64url");

  const requestedTypes = [
    "VerifiableCredential",
    "VerifiableAttestation",
    credentialType,
  ];

  const openIdCredentialIssuerUrl = inputIssuer
    ? `/client-mock/${inputIssuer}/.well-known/openid-credential-issuer`
    : "/issuer-mock/.well-known/openid-credential-issuer";

  const initiateCredentialOfferEndpoint = inputIssuer
    ? `${apiUrl}/client-mock/${inputIssuer}/initiate-credential-offer`
    : `${apiUrl}/issuer-mock/initiate-credential-offer`;

  // credentialOffer: conformance-new issuerMockInitiateCredentialOffer initiateCredentialOfferEndpoint
  console.log(
    `==> conformance-new issuerMockInitiateCredentialOffer ${initiateCredentialOfferEndpoint} ${credentialType}`
  );
  let credentialOffer: CredentialOfferPayload;
  const validTypesIssuerState = [
    "use-credential-offer",
    "skip-credential-offer",
  ];
  if (
    typeCredentialOffer &&
    !validTypesIssuerState.includes(typeCredentialOffer)
  ) {
    throw new Error(
      `invalid command for typeCredentialOffer. valid types: ${validTypesIssuerState.join(
        ", "
      )}`
    );
  }
  const useCredentialOffer = typeCredentialOffer !== "skip-credential-offer";
  const isPreauthorised = communicationType
    .toLowerCase()
    .startsWith("preauthorised");
  if (!useCredentialOffer) {
    if (isPreauthorised)
      throw new Error("For preauthorised credentials set use-credential-offer");
  } else {
    credentialOffer = await issuerMockInitiateCredentialOffer(
      [initiateCredentialOfferEndpoint, credentialType],
      context
    );
  }

  // opIssuer: conformance-new get /issuer-mock/.well-known/openid-credential-issuer
  console.log(`==> conformance-new get ${openIdCredentialIssuerUrl}`);
  const opIssuer = (await conformanceGet(
    [openIdCredentialIssuerUrl],
    context
  )) as OpenIdCredentialIssuer;

  const authorizationServer =
    opIssuer.authorization_server ?? opIssuer.credential_issuer;

  // opConf: conformance-new get opIssuer.authorization_server /.well-known/openid-configuration
  console.log(
    `==> conformance-new get ${authorizationServer}/.well-known/openid-configuration`
  );
  const opConf = (await conformanceGet(
    [authorizationServer, "/.well-known/openid-configuration"],
    context
  )) as OpenIdConfiguration;

  let code: string;
  if (isPreauthorised) {
    code =
      credentialOffer.grants[
        "urn:ietf:params:oauth:grant-type:pre-authorized_code"
      ]?.["pre-authorized_code"];
  } else {
    // respAuthorize: conformance-new authMockAuthorize opIssuer opConf requestedTypes ES256
    let issuerState = "";
    if (useCredentialOffer)
      issuerState = credentialOffer.grants.authorization_code
        ? credentialOffer.grants.authorization_code.issuer_state
        : "";
    console.log(
      `==> conformance-new authMockAuthorize ${stringify(opIssuer, [
        "authorization_server",
        "credential_issuer",
      ])} ${stringify(opConf, ["authorization_endpoint"])} ${JSON.stringify(
        requestedTypes
      )} ${alg} ${codeVerifier} ${issuerState}`
    );
    const respAuthorize = await authMockAuthorize(
      [opIssuer, opConf, requestedTypes, alg, codeVerifier, issuerState],
      context
    );

    if (credentialType === "CTWalletQualificationCredential") {
      // vpJwt: compute createPresentationJwt vc alg opConf.issuer
      console.log(
        `==> compute createPresentationJwt ${vc || "empty"} ${alg} ${
          opConf.issuer
        }`
      );
      const vpJwt = (await compute(
        "createPresentationJwt",
        [vc || "empty", alg, opConf.issuer],
        context
      )) as string;

      // respDirectPost: conformance-new authMockDirectPostVpToken opIssuer opConf respAuthorize ES256
      console.log(
        `==> conformance-new authMockDirectPostVpToken ${stringify(opConf, [
          "redirect_uris",
        ])} ${JSON.stringify(respAuthorize)} ${vpJwt} holder`
      );
      const respDirectPost = (await authMockDirectPostVpToken([
        opConf,
        respAuthorize,
        vpJwt,
        "holder",
      ])) as { code: string };
      code = respDirectPost.code;
    } else {
      // respDirectPost: conformance-new authMockDirectPostIdToken opIssuer opConf respAuthorize ES256
      console.log(
        `==> conformance-new authMockDirectPostIdToken ${stringify(opIssuer, [
          "authorization_server",
          "credential_issuer",
        ])} ${stringify(opConf, ["redirect_uris"])} ${JSON.stringify(
          respAuthorize
        )} ${alg}`
      );
      const respDirectPost = (await authMockDirectPostIdToken(
        [opIssuer, opConf, respAuthorize, alg],
        context
      )) as { code: string };
      code = respDirectPost.code;
    }
  }

  // resToken: conformance-new authMockToken opIssuer opConf respDirectPost.code ES256
  console.log(
    `==> conformance-new authMockToken ${stringify(opIssuer, [
      "authorization_server",
      "credential_issuer",
    ])} ${stringify(opConf, ["token_endpoint"])} ${code} ${alg} ${codeVerifier}`
  );
  const respToken = (await authMockToken(
    [
      opIssuer,
      opConf,
      code,
      alg,
      codeVerifier,
      isPreauthorised ? "preAuthorised" : "",
    ],
    context
  )) as { access_token: string; c_nonce: string };

  // using token resToken.access_token
  console.log(`==> using token ${respToken.access_token}`);
  context.httpOpts = {
    headers: {
      authorization: `Bearer ${respToken.access_token}`,
    },
  };

  // resCredential: conformance-new issuerMockCredential opIssuer resToken.c_nonce requestedTypes ES256
  console.log(
    `==> conformance-new issuerMockCredential ${stringify(opIssuer, [
      "credential_issuer",
    ])} ${respToken.c_nonce} ${JSON.stringify(requestedTypes)} ${alg}`
  );
  const respCredential = (await issuerMockCredential(
    [opIssuer, respToken.c_nonce, requestedTypes, alg],
    context
  )) as { credential: string; acceptance_token: string };

  let credential: string;
  const isDeferred = communicationType.toLowerCase().endsWith("deferred");
  if (isDeferred) {
    console.log(`waiting 5.5 seconds...`);
    await new Promise((r) => {
      setTimeout(r, 5500);
    });
    // respDeferred: conformance-new issuerMockDeferred respDirectPost.acceptance_token
    console.log(
      `==> conformance-new issuerMockDeferred ${stringify(opIssuer, [
        "deferred_credential_endpoint",
      ])} ${respCredential.acceptance_token}`
    );
    const respDeferred = (await issuerMockDeferred([
      opIssuer,
      respCredential.acceptance_token,
    ])) as { credential: string };
    credential = respDeferred.credential;
  } else {
    credential = respCredential.credential;
  }

  return credential;
}

export async function check(inputs: unknown, context: Context) {
  const [intent, preAuthorizedCode, userPin] = inputs as [
    string,
    string,
    string
  ];
  const apiUrl = context.config.api["conformance-new"].url;
  const response = await httpCall.post<{ success: boolean; errors?: string[] }>(
    `${apiUrl}/check`,
    {
      data: {
        clientId: context.client.clientId,
        did: context.client.did,
        credentialIssuer: context.client.clientId,
        credentialIssuerDid: context.client.did,
        issuerState: context.client.issuerState,
        ...(preAuthorizedCode && {
          preAuthorizedCode,
          userPin,
        }),
      },
      intent,
    }
  );
  if (!response.data.success) {
    red(response.data.errors);
    throw new Error(
      `check ${intent} failed: ${
        response.data.errors
          ? JSON.stringify(response.data.errors)
          : "unknown error"
      }`
    );
  }
  return response.data;
}

export async function conformanceV4(
  method: string,
  inputs: (string | UnknownObject)[],
  context: Context
): Promise<unknown> {
  switch (method) {
    case "get": {
      return conformanceGet(inputs as string[], context);
    }

    case "clientMockInitiate": {
      return clientMockInitiate(context);
    }

    case "clientMockUpdateList": {
      return clientMockUpdateList(inputs as string[], context);
    }

    case "authMockAuthorize": {
      return authMockAuthorize(inputs, context);
    }

    case "authMockDirectPostIdToken": {
      return authMockDirectPostIdToken(inputs, context);
    }

    case "authMockDirectPostVpToken": {
      return authMockDirectPostVpToken(inputs);
    }

    case "authMockToken": {
      return authMockToken(inputs, context);
    }

    case "issuerMockCredential": {
      return issuerMockCredential(inputs, context);
    }

    case "issuerMockDeferred": {
      return issuerMockDeferred(inputs);
    }

    case "issuerMockInitiateCredentialOffer": {
      return issuerMockInitiateCredentialOffer(inputs, context);
    }

    case "getCredential": {
      return getCredential(inputs, context);
    }

    case "holder": {
      return holder(inputs, context);
    }

    case "check": {
      return check(inputs, context);
    }

    default:
      red(`Invalid method '${method}'`);
      return 0;
  }
}

export default conformanceV4;
