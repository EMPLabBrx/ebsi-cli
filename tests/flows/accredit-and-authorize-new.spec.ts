import { describe, it, expect, vi, beforeAll } from "vitest";
import { decodeJwt } from "jose";
// eslint-disable-next-line import/no-extraneous-dependencies
import { sha256 } from "@ethersproject/sha2";
import { loadConfig } from "../../src/config.js";
import { execCommand } from "../../src/app.js";
import { Client } from "../../src/utils/index.js";

const mockConsole = vi.spyOn(console, "log");
mockConsole.mockImplementation(() => {});

const config = loadConfig();

let myIssuer: ReturnType<(typeof Client)["prototype"]["toJSON"]>;
let proxyId: string;
let vcTI: {
  vc: string;
  reservedAttributeId: string;
  url?: string;
};
let vcTAO: {
  vc: string;
  reservedAttributeId: string;
  url?: string;
};
let vcRootTAO: {
  vc: string;
  reservedAttributeId: string;
  url?: string;
};

describe("Accredit and Authorize", () => {
  beforeAll(async () => {
    await execCommand(`set domain ${config.domain}`);

    // create keys for the new issuer
    await execCommand("using user ES256K");
    await execCommand("using user ES256");
    myIssuer = await execCommand("set myIssuer user");
  });

  it("should request credential to onboard", async () => {
    expect.assertions(3);

    const vcOnboard = await execCommand<{ vc: string }>(
      "vcOnboard: conformance-new getCredential onboard"
    );

    expect(vcOnboard).toStrictEqual({
      vc: expect.any(String) as string,
      reservedAttributeId: "",
    });
    expect(decodeJwt(vcOnboard.vc)).toStrictEqual(
      expect.objectContaining({
        vc: expect.objectContaining({
          type: expect.arrayContaining([
            "VerifiableAuthorisationToOnboard",
          ]) as unknown,
        }) as unknown,
      }) as unknown
    );

    const check = await execCommand(
      "conformance-new check ti_request_verifiable_authorisation_to_onboard"
    );
    expect(check).toStrictEqual({ success: true });
  });

  it("should register the DID document", async () => {
    expect.assertions(2);

    await execCommand("run new/registerDidDocument_ES256K_ES256 vcOnboard.vc");
    const didDocument = await execCommand(
      "did-new get /identifiers/ myIssuer.did"
    );
    expect(didDocument).toStrictEqual(
      expect.objectContaining({
        id: myIssuer.did,
        controller: [myIssuer.did],
        verificationMethod: [
          {
            id: myIssuer.keys.ES256K.kid,
            type: "JsonWebKey2020",
            controller: myIssuer.did,
            publicKeyJwk: myIssuer.keys.ES256K.publicKeyJwk,
          },
          {
            id: myIssuer.keys.ES256.kid,
            type: "JsonWebKey2020",
            controller: myIssuer.did,
            publicKeyJwk: myIssuer.keys.ES256.publicKeyJwk,
          },
        ],
        authentication: [myIssuer.keys.ES256K.kid, myIssuer.keys.ES256.kid],
        assertionMethod: [myIssuer.keys.ES256.kid],
        capabilityInvocation: [myIssuer.keys.ES256K.kid],
      }) as unknown
    );

    const check = await execCommand("conformance-new check ti_register_did");
    expect(check).toStrictEqual({ success: true });
  });

  it("should request VerifiableAccreditationToAttest (TI)", async () => {
    expect.assertions(3);

    vcTI = await execCommand<{ vc: string; reservedAttributeId: string }>(
      "vcTI: conformance-new getCredential ti"
    );
    await execCommand(
      `set vcTI.url ${config.api["tir-new"].url}/issuers/ myIssuer.did /attributes/ vcTI.reservedAttributeId`
    );
    expect(vcTI).toStrictEqual({
      vc: expect.any(String) as string,
      reservedAttributeId: expect.any(String) as string,
      url: expect.any(String) as string,
    });
    expect(decodeJwt(vcTI.vc)).toStrictEqual(
      expect.objectContaining({
        vc: expect.objectContaining({
          type: expect.arrayContaining([
            "VerifiableAccreditationToAttest",
          ]) as unknown,
          credentialSubject: expect.objectContaining({
            reservedAttributeId: vcTI.reservedAttributeId,
          }) as unknown,
        }) as unknown,
      })
    );

    const check = await execCommand(
      "conformance-new check ti_request_verifiable_accreditation_to_attest"
    );
    expect(check).toStrictEqual({ success: true });
  });

  it("should register the VerifiableAccreditationToAttest in the TIR", async () => {
    expect.assertions(2);

    await execCommand(
      "t: authorisation-new auth tir_invite_presentation ES256 vcTI.vc"
    );
    await execCommand("using token t.access_token");
    await execCommand(
      "tir-new setAttributeData myIssuer.did vcTI.reservedAttributeId vcTI.vc"
    );
    const attribute = await execCommand(
      "tir-new get /issuers/ myIssuer.did /attributes/ vcTI.reservedAttributeId"
    );
    expect(attribute).toStrictEqual({
      did: myIssuer.did,
      attribute: {
        hash: expect.any(String) as string,
        body: vcTI.vc,
        issuerType: "TI",
        tao: expect.any(String) as string,
        rootTao: expect.any(String) as string,
      },
    });

    const check = await execCommand(
      "conformance-new check ti_register_verifiable_accreditation_to_attest"
    );
    expect(check).toStrictEqual({ success: true });
  });

  it("should register a proxy in the Trusted Issuers Registry", async () => {
    expect.assertions(1);

    // setup server to resolve status list
    const id = "1";
    const statusListId = "0";
    const value = "0";
    await execCommand(
      `conformance-new clientMockUpdateList ${id} ${statusListId} ${value}`
    );
    await execCommand("t: authorisation-new auth tir_write_presentation ES256");
    await execCommand("using token t.access_token");
    const proxyData = JSON.stringify({
      prefix: myIssuer.clientId,
      headers: {},
      testSuffix: "/credentials/status/1",
    });
    proxyId = sha256(Buffer.from(proxyData));

    await execCommand(`set user.proxyId ${proxyId}`);
    await execCommand("set user.accreditationUrl vcTI.url");
    await execCommand("conformance-new clientMockInitiate");

    // register proxy id
    await execCommand(`tir-new addIssuerProxy myIssuer.did ${proxyData}`);
    const response = await execCommand(
      "tir-new get /issuers/ myIssuer.did /proxies"
    );

    // check registration
    expect(response).toStrictEqual({
      items: [
        {
          proxyId,
          href: `${config.domain}/trusted-issuers-registry/v5/issuers/${myIssuer.did}/proxies/${proxyId}`,
        },
      ],
      total: 1,
    });
  });

  it("should issue a CTRevocable credential", async () => {
    expect.assertions(1);

    const check = await execCommand(
      "conformance-new check ti_request_ctrevocable"
    );
    expect(check).toStrictEqual({ success: true });
  });

  it("should validate the CTRevocable issued", async () => {
    expect.assertions(1);

    const check = await execCommand(
      "conformance-new check ti_validate_ctrevocable"
    );
    expect(check).toStrictEqual({ success: true });
  });

  it("should revoke CTRevocable credential", async () => {
    expect.assertions(1);

    await execCommand(
      `statusListIndex: compute statusListIndex ${config.api["conformance-new"].did}`
    );
    await execCommand(
      "conformance-new clientMockUpdateList 1 statusListIndex 1"
    );

    const check = await execCommand(
      "conformance-new check ti_revoke_ctrevocable"
    );
    expect(check).toStrictEqual({ success: true });
  });

  it("should request VerifiableAccreditationToAccredit (TAO)", async () => {
    expect.assertions(3);

    vcTAO = await execCommand<{ vc: string; reservedAttributeId: string }>(
      "vcTAO: conformance-new getCredential tao"
    );
    await execCommand(
      `set vcTAO.url ${config.api["tir-new"].url}/issuers/ myIssuer.did /attributes/ vcTAO.reservedAttributeId`
    );
    expect(vcTAO).toStrictEqual({
      vc: expect.any(String) as string,
      reservedAttributeId: expect.any(String) as string,
      url: expect.any(String) as string,
    });
    expect(decodeJwt(vcTAO.vc)).toStrictEqual(
      expect.objectContaining({
        vc: expect.objectContaining({
          type: expect.arrayContaining([
            "VerifiableAccreditationToAccredit",
          ]) as unknown,
          credentialSubject: expect.objectContaining({
            reservedAttributeId: vcTAO.reservedAttributeId,
          }) as unknown,
        }) as unknown,
      }) as unknown
    );

    const check = await execCommand(
      "conformance-new check tao_request_verifiable_accreditation_to_accredit"
    );
    expect(check).toStrictEqual({ success: true });
  });

  it("should register the VerifiableAccreditationToAccredit in the TIR", async () => {
    expect.assertions(2);

    await execCommand("t: authorisation-new auth tir_write_presentation ES256");
    await execCommand("using token t.access_token");
    await execCommand(
      "tir-new setAttributeData myIssuer.did vcTAO.reservedAttributeId vcTAO.vc"
    );
    await execCommand(
      `set vcTAO.url ${config.api["tir-new"].url}/issuers/ myIssuer.did /attributes/ vcTAO.reservedAttributeId`
    );
    await execCommand("set user.accreditationUrl vcTAO.url");
    await execCommand("conformance-new clientMockInitiate");
    const attribute = await execCommand(
      "tir-new get /issuers/ myIssuer.did /attributes/ vcTAO.reservedAttributeId"
    );
    expect(attribute).toStrictEqual({
      did: myIssuer.did,
      attribute: {
        hash: expect.any(String) as string,
        body: vcTAO.vc,
        issuerType: "TAO",
        tao: expect.any(String) as string,
        rootTao: expect.any(String) as string,
      },
    });

    const check = await execCommand(
      "conformance-new check tao_register_verifiable_accreditation_to_accredit"
    );
    expect(check).toStrictEqual({ success: true });
  });

  it("should issue a VC to onboard a subaccount", async () => {
    expect.assertions(1);

    const check = await execCommand(
      "conformance-new check tao_request_verifiable_authorisation_to_onboard_subaccount"
    );
    expect(check).toStrictEqual({ success: true });
  });

  it("should validate credential and register did document of the subaccount", async () => {
    expect.assertions(1);

    const check = await execCommand(
      "conformance-new check tao_validate_verifiable_authorisation_to_onboard_subaccount"
    );
    expect(check).toStrictEqual({ success: true });
  });

  it("should issue a VerifiableAccreditationToAttest for the subaccount (TI subaccount)", async () => {
    expect.assertions(1);

    const check = await execCommand(
      "conformance-new check tao_request_verifiable_accreditation_to_attest_subaccount"
    );
    expect(check).toStrictEqual({ success: true });
  });

  it("should validate credential and register VerifiableAccreditationToAttest for the subaccount (TI subaccount)", async () => {
    expect.assertions(1);

    const check = await execCommand(
      "conformance-new check tao_validate_verifiable_accreditation_to_attest_subaccount"
    );
    expect(check).toStrictEqual({ success: true });
  });

  it("should issue a VerifiableAccreditationToAccredit for the subaccount (TAO subaccount)", async () => {
    expect.assertions(1);

    const check = await execCommand(
      "conformance-new check tao_request_verifiable_accreditation_to_accredit_subaccount"
    );
    expect(check).toStrictEqual({ success: true });
  });

  it("should validate credential and register VerifiableAccreditationToAccredit for the subaccount (TAO subaccount)", async () => {
    expect.assertions(1);

    const check = await execCommand(
      "conformance-new check tao_validate_verifiable_accreditation_to_accredit_subaccount"
    );
    expect(check).toStrictEqual({ success: true });
  });

  it("should revoke credentials issued to subaccount", async () => {
    expect.assertions(1);

    await execCommand("subaccount: compute subaccountDid myIssuer.did");
    await execCommand(
      "attributes: tir-new get /issuers/ subaccount /attributes"
    );
    await execCommand("t: authorisation-new auth tir_write_presentation ES256");
    await execCommand("using token t.access_token");
    await execCommand(
      "tir-new setAttributeMetadata subaccount attributes.items.0.id revoked myIssuer.did vcTAO.reservedAttributeId"
    );
    await execCommand(
      "tir-new setAttributeMetadata subaccount attributes.items.1.id revoked myIssuer.did vcTAO.reservedAttributeId"
    );

    const check = await execCommand(
      "conformance-new check tao_revoke_rights_subaccount"
    );
    expect(check).toStrictEqual({ success: true });
  });

  it("should request VerifiableAuthorisationForTrustChain (RootTAO)", async () => {
    expect.assertions(3);

    vcRootTAO = await execCommand<{ vc: string; reservedAttributeId: string }>(
      "vcRootTAO: conformance-new getCredential roottao ES256 vcOnboard.vc"
    );
    await execCommand(
      `set vcRootTAO.url ${config.api["tir-new"].url}/issuers/ myIssuer.did /attributes/ vcRootTAO.reservedAttributeId`
    );
    expect(vcRootTAO).toStrictEqual({
      vc: expect.any(String) as string,
      reservedAttributeId: expect.any(String) as string,
      url: expect.any(String) as string,
    });
    expect(decodeJwt(vcRootTAO.vc)).toStrictEqual(
      expect.objectContaining({
        vc: expect.objectContaining({
          type: expect.arrayContaining([
            "VerifiableAuthorisationForTrustChain",
          ]) as unknown,
          credentialSubject: expect.objectContaining({
            reservedAttributeId: vcRootTAO.reservedAttributeId,
          }) as unknown,
        }) as unknown,
      }) as unknown
    );

    const check = await execCommand(
      "conformance-new check rtao_request_verifiableauthorisationfortrustchain"
    );
    expect(check).toStrictEqual({ success: true });
  });

  it("should register the VerifiableAuthorisationForTrustChain in the TIR", async () => {
    expect.assertions(2);

    await execCommand("t: authorisation-new auth tir_write_presentation ES256");
    await execCommand("using token t.access_token");
    await execCommand(
      "tir-new setAttributeData myIssuer.did vcRootTAO.reservedAttributeId vcRootTAO.vc"
    );
    const attribute = await execCommand(
      "tir-new get /issuers/ myIssuer.did /attributes/ vcRootTAO.reservedAttributeId"
    );
    expect(attribute).toStrictEqual({
      did: myIssuer.did,
      attribute: {
        hash: expect.any(String) as string,
        body: vcRootTAO.vc,
        issuerType: "RootTAO",
        tao: expect.any(String) as string,
        rootTao: expect.any(String) as string,
      },
    });

    const check = await execCommand(
      "conformance-new check rtao_register_verifiableauthorisationfortrustchain"
    );
    expect(check).toStrictEqual({ success: true });
  });

  it("should request CTAAQualificationCredential", async () => {
    expect.assertions(1);

    // Wait ~10 seconds to let Loki retrieve the logs
    await new Promise<void>((resolve) => {
      setTimeout(() => resolve(), 10_000);
    });

    await execCommand(
      "ctaaQualification: conformance-new getCredential qualification"
    );

    const check = await execCommand(
      "conformance-new check request_ctaaqualificationcredential"
    );
    expect(check).toStrictEqual({ success: true });
  });
});
