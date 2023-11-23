import { describe, it, expect, vi } from "vitest";
import crypto from "node:crypto";
import { EbsiWallet } from "@cef-ebsi/wallet-lib";
import { loadConfig, UserDetails } from "../../src/config.js";
import { execCommand } from "../../src/app.js";
import ebsiExtended from "../utils/ebsi-extended.js";

expect.extend(ebsiExtended);
const mockConsole = vi.spyOn(console, "log");
mockConsole.mockImplementation(() => {});

const config = loadConfig();
const { issuer1, issuer2, requesterApp, resourceApp, user1 } = config.vitestNew;

const newLE = {
  did: EbsiWallet.createDid(),
  privateKey: crypto.randomBytes(32).toString("hex"),
};

async function loadUser(user: UserDetails, tokenName?: string): Promise<void> {
  await execCommand("using user null");
  await execCommand(
    `using user ES256K did1 ${user.privateKey} ${user.did} ${user.keyId ?? ""}`
  );
  if (user.jwks && user.jwks.ES256) {
    await execCommand(
      `using user ES256 did1 ${Buffer.from(
        user.jwks.ES256.privateKeyBase64,
        "base64"
      ).toString()} ${user.did} ${user.jwks.ES256.keyId ?? ""}`
    );
  }
  if (tokenName) await execCommand(`using token ${tokenName}`);
}

describe("Authorisation (e2e)", () => {
  it("should get the open id configuration", async () => {
    const openIdConfig = await execCommand<{ issuer: string }>(
      "authorisation-new get /.well-known/openid-configuration"
    );
    expect(openIdConfig).toStrictEqual({
      authorization_endpoint: `${config.domain}/authorisation/v4/authorize`,
      grant_types_supported: ["vp_token"],
      id_token_signing_alg_values_supported: ["none"],
      id_token_types_supported: ["subject_signed_id_token"],
      issuer: `${config.domain}/authorisation/v4`,
      jwks_uri: `${config.domain}/authorisation/v4/jwks`,
      presentation_definition_endpoint: `${config.domain}/authorisation/v4/presentation-definitions`,
      response_types_supported: ["token"],
      scopes_supported: [
        "openid",
        "didr_invite",
        "didr_write",
        "tir_invite",
        "tir_write",
        "timestamp_write",
      ],
      subject_syntax_types_supported: ["did:ebsi", "did:key"],
      subject_trust_frameworks_supported: ["ebsi"],
      subject_types_supported: ["public"],
      token_endpoint: `${config.domain}/authorisation/v4/token`,
      token_endpoint_auth_methods_supported: ["private_key_jwt"],
      vp_formats_supported: {
        jwt_vc: {
          alg_values_supported: ["ES256"],
        },
        jwt_vp: {
          alg_values_supported: ["ES256"],
        },
      },
    });
  });

  it("should get an access token for scope didr_invite (onboard new legal entity)", async () => {
    expect.assertions(1);
    const payloadVcOnboard = {
      "@context": ["https://www.w3.org/2018/credentials/v1"],
      type: [
        "VerifiableCredential",
        "VerifiableAttestation",
        "VerifiableAuthorisationToOnboard",
      ],
      issuer: issuer1.did,
      credentialSubject: {
        id: newLE.did,
        accreditedFor: [],
      },
      termsOfUse: {
        id: issuer1.accreditation,
        type: "IssuanceCertificate",
      },
      credentialSchema: {
        id: `${config.domain}/trusted-schemas-registry/v3/schemas/z3MgUFUkb722uq4x3dv5yAJmnNmzDFeK5UC8x83QoeLJM`,
        type: "FullJsonSchemaValidator2021",
      },
    };
    await loadUser(issuer1);
    const vcToOnboard = await execCommand<string>(
      `compute createVcJwt ${JSON.stringify(payloadVcOnboard)} {} ES256`
    );

    await loadUser(newLE);
    const result = await execCommand(
      `authorisation-new auth didr_invite_presentation ES256K ${vcToOnboard}`
    );
    expect(result).toStrictEqual({
      access_token: expect.any(String) as string,
      expires_in: expect.any(Number) as number,
      id_token: expect.any(String) as string,
      scope: "openid didr_invite",
      token_type: "Bearer",
    });
  });

  it("should get an access token for scope didr_write", async () => {
    expect.assertions(1);

    await loadUser(issuer1);
    const result = await execCommand(
      "authorisation-new auth didr_write_presentation ES256K"
    );
    expect(result).toStrictEqual({
      access_token: expect.any(String) as string,
      expires_in: expect.any(Number) as number,
      id_token: expect.any(String) as string,
      scope: "openid didr_write",
      token_type: "Bearer",
    });
  });

  it("should get an access token for scope tir_invite", async () => {
    expect.assertions(1);

    // create a VC to Attest
    await loadUser(issuer1);
    await execCommand(
      `payloadVcTI: load scripts/assets/VerifiableAccreditationToAttest.json`
    );
    await execCommand(`set payloadVcTI.issuer ${issuer1.did}`);
    await execCommand(`set payloadVcTI.credentialSubject.id ${issuer2.did}`);
    await execCommand(
      `set payloadVcTI.credentialSchema.id ${config.domain}/trusted-schemas-registry/v3/schemas/zjVFNvbEBPAr3a724DttioZpgZmNr75BBtRzZqk7pkDe`
    );
    await execCommand(`set payloadVcTI.termsOfUse.id ${issuer1.accreditation}`);
    const vcToAttest = await execCommand<string>(
      `compute createVcJwt payloadVcTI {} ES256K`
    );

    await loadUser(issuer2);
    const result = await execCommand(
      `authorisation-new auth tir_invite_presentation ES256K ${vcToAttest}`
    );
    expect(result).toStrictEqual({
      access_token: expect.any(String) as string,
      expires_in: expect.any(Number) as number,
      id_token: expect.any(String) as string,
      scope: "openid tir_invite",
      token_type: "Bearer",
    });
  });

  it("should get an access token for scope tir_write", async () => {
    expect.assertions(1);

    await loadUser(issuer1);
    const result = await execCommand(
      "authorisation-new auth tir_write_presentation ES256K"
    );
    expect(result).toStrictEqual({
      access_token: expect.any(String) as string,
      expires_in: expect.any(Number) as number,
      id_token: expect.any(String) as string,
      scope: "openid tir_write",
      token_type: "Bearer",
    });
  });

  it("should create an OAuth2 session", async () => {
    expect.assertions(1);
    await execCommand(
      `using app-new ${requesterApp.name} ${requesterApp.privateKey}`
    );
    const token = await execCommand(
      `authorisation-new oauth2 ${resourceApp.name}`
    );
    expect(token).toBeJwt();
  });

  describe.each(["ES256K", "ES256", "RS256", "EdDSA"])(
    "POST /siop-sessions with alg %s",
    (alg) => {
      it("should create a SIOP session for a known user (legal entity)", async () => {
        expect.assertions(1);
        let privateKey: string;
        let keyId: string;
        if (alg === "ES256K") {
          privateKey = user1.privateKey;
          keyId = user1.keyId;
        } else {
          const key = user1.jwks[alg] as {
            privateKeyBase64: string;
            keyId: string;
          };
          privateKey = Buffer.from(key.privateKeyBase64, "base64").toString();
          keyId = key.keyId;
        }

        await execCommand(
          `using user ${alg} did1 ${privateKey} ${user1.did} ${keyId}`
        );

        const token = await execCommand(`authorisation-new siop ${alg}`);
        expect(token).toBeJwt();
      });
    }
  );
});
